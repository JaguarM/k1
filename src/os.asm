; os.asm - bare-metal HTTPS server, flat multiboot image (nasm -f bin)
;
; Boot: multiboot v1 "a.out kludge", loaded at 1 MiB by `qemu -kernel`.
; NIC:  ISA NE2000 at port 0x300, polled.  Network: slirp (10.0.2.15).
; TLS:  1.3, TLS_CHACHA20_POLY1305_SHA256, X25519, ecdsa_secp256r1_sha256.
; See CLAUDE.md for the (many, deliberate) shortcuts.
;
; Convention: every routine preserves all registers (pushad/popad) unless it
; says otherwise. All buffers live at fixed addresses in zeroed RAM at 2 MiB.

BITS 32

BSS     equ 0x200000
FR      equ 0               ; Ethernet frame: received, then rewritten in place as reply.
                            ; At address 0 (old real-mode IVT, unused) so `xor reg, reg` loads it.
TR      equ BSS + 0x00800   ; handshake transcript
OB      equ BSS + 0x02800   ; TLS output for one TCP reply
SB      equ BSS + 0x07800   ; seal scratch: Poly1305 input
HB      equ BSS + 0x0C900   ; HMAC buffer (key pad | message)
INFO    equ HB + 64         ; HKDF info is built right where HMAC wants its message
AW      equ BSS + 0x0CB00   ; SHA-256 a..h sliding down 64 dwords, with W[] stored above it
SH      equ BSS + 0x0CD20   ; SHA-256 chaining value
ST      equ BSS + 0x0CD40   ; ChaCha20 state
KS      equ BSS + 0x0CD80   ; ChaCha20 key stream block (64-byte aligned)
PK      equ BSS + 0x0CDC0   ; Poly1305 key block
XT      equ BSS + 0x0CE00   ; Poly1305 h * r, 17 dwords
PH      equ BSS + 0x0D300   ; Poly1305 h: 17 limbs of 8 bits (the top one: 2) in dwords
RR      equ PH + 72         ; R[0..32] (R[-1] = PH + 68 is junk): see poly1305
SLOTS   equ BSS + 0x0D500   ; key schedule values, 8 x 32 bytes, addressed from ebp
KH      equ BSS + 0x0D600   ; handshake traffic key | 0 counter | iv
CVB     equ BSS + 0x0D680   ; CertificateVerify content to be signed (+ room for padding)
KT      equ BSS + 0x0D800   ; SHA-256 round constants (computed at boot), 64 dwords; 512-aligned
HT      equ KT + 0x104      ; SHA-256 initial hash (computed at boot), 8 dwords (+ 56 junk)
CHB     equ 0x400000        ; ClientHello reassembly: 1024 x 4 KiB, by slirp's initial seq
CONNS   equ 0x800000        ; 65536 connections x 128 bytes: one slot per client port

S_Z     equ -128            ; slot offsets from ebp = SLOTS + 128
S_EH    equ -96
S_ES    equ -64
S_D     equ -32
S_HS    equ 0
S_TS    equ 32
S_TH    equ 64

C_ST    equ 0               ; connection: record counter (0 = waiting for the ClientHello)
C_NXT   equ 4               ; next sequence number we expect from the client
C_LEN   equ 8               ; ClientHello bytes so far; then bytes left of the current record
C_KIV   equ 12              ; application key | 0 counter | iv (+20 bytes of junk: `keys`)

%ifdef HOST
        section .text
        global sha256, hmac, expand, seal, shaconst
%else
        org 0x100000
mb:     dd 0x1BADB002, 0x00010000, -(0x1BADB002 + 0x00010000)
        dd mb, mb, 0, PUB+32, start ; bss_end: the loader zero-fills PUB's tail

; ----------------------------------------------------------------------------
start:                          ; QEMU's multiboot loader leaves esp = 0x6f10: good enough
%endif
; shaconst: SHA-256 constants from their definition: KT[i] = frac(cbrt(prime i)) * 2^32
; (Newton's method, so only exactly rounded x87 ops), HT[i] = frac(sqrt(prime i)) * 2^32.
; Inlined into the boot path; a function only in the host test build.
%ifdef HOST
shaconst:
        pushad
%endif
        mov edi, KT-4           ; the loop also counts 1 as a prime: its entry lands at KT-4
        push 3
        xor ebx, ebx            ; prime candidate
.np:    inc ebx
        mov ecx, ebx
.td:    dec ecx                 ; trial division by ebx-1 .. 2
        cmp ecx, 1
        jbe .pr
        mov eax, ebx
        cdq
        div ecx
        test edx, edx
        jnz .td
        jmp .np
.pr:    push ebx
        fild dword [esp]        ; p
        fld st0                 ; y = p
        mov cl, 40
.nw:    fld st0
        fmul st0, st0
        fdivr st0, st2          ; p / y^2
        fadd st0, st1
        faddp st1, st0
        fidiv dword [esp+4]     ; y = (2y + p/y^2) / 3
        loop .nw
        fmul dword [TWO32]
        fisttp qword [edi]      ; low dword = fraction bits (the next entry overwrites the rest)
        fsqrt                   ; (only the first 8 matter; the rest land in junk space)
        fmul dword [TWO32]
        fisttp qword [edi+HT-KT]
        pop eax
        scasd
        bt edi, 8               ; KT is 512-aligned: bit 8 first sets at KT+256
        jnc .np
        pop eax
%ifdef HOST
        popad
        ret
%else
        mov esi, nicinit        ; NE2000 setup: (register, value) pairs
        mov dh, 3
        push 7
        pop ecx
.ni:    lodsw
        mov dl, al
        mov al, ah
        out dx, al
        loop .ni

        xor ebx, ebx            ; FR: unsolicited ARP reply "10.0.2.15 is at <whatever MAC>"
        mov word [ebx+12], 0x0608 ; (the MAC is IVT junk: fine, the NIC is promiscuous)
        mov word [ebx+20], 0x0200
        mov dword [ebx+28], 0x0f02000a
        push 42
        pop ecx
        call nic_send

        mov bl, 0x46            ; next page to read (PSTART); dh = 3 from here on
.poll:  mov dl, 0
        mov al, 0x40
        out dx, al              ; register page 1
        mov dl, 7
        in al, dx               ; CURR: page the NIC will write next
        cmp al, bl
        je .poll
        mov dl, 0
        xor eax, eax
        out dx, al              ; register page 0
        mov dl, 8
        out dx, al              ; remote DMA address = next page << 8
        inc edx
        mov al, bl
        out dx, al
        mov dl, 0x10
        in eax, dx              ; packet header: status, next page, length (QEMU allows 32-bit)
        mov bl, ah
        shr eax, 16
        xchg eax, ecx           ; (reads 4 bytes past the frame: harmless)
        xor edi, edi            ; FR
        rep insb
        mov al, bl
        mov dl, 3
        out dx, al              ; BNRY: free what we read
        pushad
        call tcp
        popad
        jmp .poll

; nic_send: transmit ecx bytes from FR
nic_send:
        pushad
        mov dx, 0x308
        xor eax, eax
        out dx, al              ; remote DMA address 0x4000 (TX page)
        inc edx
        mov al, 0x40
        out dx, al
        mov dl, 0x0b
        out dx, al              ; remote byte count high = 0x40: enough for a full frame
        mov dl, 0x10
        xor esi, esi            ; FR
        rep outsb
        xchg eax, esi           ; = length, since FR = 0
        mov dl, 5
        out dx, al              ; transmit byte count
        inc edx
        mov al, ah
        out dx, al
        mov dl, 0
        mov al, 4
        out dx, al              ; transmit
        popad
nsret:  ret

; ----------------------------------------------------------------------------
; tcp: handle the TCP segment in FR. Our seq = their ack (nothing we send gets lost), but
; we track the next byte we expect, so segments slirp resends (or sends after one that our
; NIC dropped while we were busy) are only re-acked.
tcp:
        xor ebx, ebx            ; FR
        cmp byte [ebx+13], 0    ; IPv4 only (slirp also sends ARP and IPv6)
        jne nsret
        movzx eax, byte [ebx+46]
        shr eax, 2              ; TCP header length
        movzx ecx, word [ebx+16]
        xchg cl, ch
        sub ecx, 20
        sub ecx, eax            ; payload length
        lea esi, [ebx+eax+34]
        mov ebp, [ebx+33]       ; 15 (our IP's last byte) | client port | 1 (443 >> 8)
        shr ebp, 1              ; connection slot: CONNS + 7 + port (bytes swapped) * 128
        mov dl, [ebx+47]        ; flags
        mov eax, [ebx+42]
        xchg eax, [ebx+38]      ; our seq = their ack; eax = their seq
        bswap eax
        test dl, 2
        jz .ns
        inc eax                 ; SYN: a new connection; the SYN takes a sequence number
        mov [ebp+C_NXT], eax    ; (so the check below passes, with nothing to add)
        mov [ebp+C_ST], ecx     ; (a SYN carries no payload: ecx = 0)
        mov [ebp+C_LEN], eax    ; until the ClientHello is in: slirp's ISN + 1
.ns:    push edx                ; flags
        push ecx                ; payload length: anything with data gets an answer
        sub eax, [ebp+C_NXT]
        jz .in
        mul ebx                 ; not the next byte we expect: ignore it, just re-ack
        xchg eax, ecx           ; (eax = edx = ecx = 0)
.in:    shr dl, 1               ; CF = FIN, which takes a sequence number
        adc [ebp+C_NXT], ecx
        mov eax, [ebp+C_NXT]
        bswap eax
        mov [ebx+42], eax       ; our ack
        mov eax, [ebx+26]
        xchg eax, [ebx+30]
        mov [ebx+26], eax       ; swap IP addresses
        rol dword [ebx+34], 16  ; swap ports
        mov edi, OB             ; edi = end of our output
        push edi
        cmp [ebp+C_ST], ebx
        je .ch
.walk:  mov eax, [ebp+C_LEN]    ; bytes of the current record still to come
.w:     sub ecx, eax            ; skip whole records; we only read their headers
        jbe .wend
        add esi, eax
        movzx eax, word [esi+3]
        xchg al, ah
        add eax, 5              ; record length
        cmp byte [esi], 23      ; application_data (alerts/Finished look the same)
        jne .w
        mov edx, [ebp+C_ST]
        inc dword [ebp+C_ST]
        dec edx
        jz .w                   ; the 1st one is the client Finished
        dec edx                 ; then every record is a request: answer it
        push esi
        push ecx
        mov esi, RESP
        push RESP_LEN           ; (imm8 form while the response is < 128 bytes)
        pop ecx
        lea ebx, [ebp+C_KIV]
        call seal               ; (keeps eax)
        pop ecx
        pop esi
        jmp .w
.ch:    mov edx, [ebp+C_LEN]    ; still waiting for the ClientHello: collect it in a bucket
        mov eax, [ebp+C_NXT]
        sub eax, edx            ; bytes so far, this segment included
        shl edx, 13             ; slirp's ISN + 1 = 2 + 64000 n, n += 1 per connection:
        shr edx, 10             ; 16 + 4 KiB * (125 n mod 1024), so 1024 in a row differ
        bts edx, 22             ; + CHB
        push edi
        lea edi, [edx+eax]
        sub edi, ecx
        rep movsb
        pop edi
        movzx ecx, word [edx+3]
        xchg cl, ch             ; record body length
        sub eax, 5
        cmp eax, ecx
        jl .send                ; not all there yet (signed: a slot that never saw a SYN)
        inc dword [ebp+C_ST]
        lea esi, [edx+5]
        call handshake
        xor ecx, ecx            ; C_LEN = 0: the next record starts with the client's next byte
.wend:  neg ecx
        mov [ebp+C_LEN], ecx
.send:  pop esi                 ; OB
        pop ecx                 ; payload length
        pop eax                 ; flags
        and eax, 3
        or ecx, eax
        jnz .tx
        ret                     ; pure ACK: stay quiet
.tx:    or al, 0x18             ; ACK|PSH (+SYN or FIN)
        mov ecx, edi
        sub ecx, esi            ; all in one segment: the largest reply, our flight, is ~400 bytes

; tcp_out (falls through from tcp): send ecx bytes at esi with flags al, reusing the swapped
; headers in FR
tcp_out:
        xor ebx, ebx            ; FR
        mov ebp, ecx            ; payload length
        mov [ebx+47], al
        lea edi, [ebx+54]
        rep movsb
        mov [edi], cl           ; zero pad byte for an odd length checksum
        lea ecx, [ebp+20]       ; TCP length
        mov eax, ecx
        xchg al, ah
        mov [ebx+24], ax        ; pseudo header in place: 0, 6 (still there: protocol TCP),
        mov [ebx+22], bl        ; length, then the IPs
        mov byte [ebx+46], 0x50 ; no options (the window stays whatever slirp offered us)
        and dword [ebx+50], 0
        lea esi, [ebx+22]
        add ecx, 12
        call csum
        mov [ebx+50], ax
        lea ecx, [ebp+40]
        xchg cl, ch
        mov [ebx+16], cx        ; IP total length
        mov dword [ebx+22], 0x0640 ; TTL 64, TCP, checksum 0
        lea esi, [ebx+14]
        push 20
        pop ecx
        call csum
        mov [ebx+24], ax
        lea ecx, [ebp+54]
        jmp nic_send

; csum: eax = internet checksum of ecx bytes at esi (clobbers ecx, edx, esi).
; dec leaves CF alone, so the end-around carry rides through the loop in adc.
csum:
        xor edx, edx
.l:     lodsw
        adc dx, ax
        dec ecx
        dec ecx
        jg .l
        adc dx, 0
        not edx
        xchg eax, edx
        ret

; ----------------------------------------------------------------------------
; handshake: ClientHello message at esi (ecx bytes), connection at ebp.
; Writes ServerHello + encrypted flight to OB, returns edi = end. Clobbers all but ebp.
handshake:
        push ebp
        mov edi, TR             ; transcript: ClientHello
        push esi
        rep movsb
        pop esi
        movzx edx, byte [esi+38] ; session id length
        lea ecx, [edx+39]
        mov ebx, edi
        rep movsb               ; ServerHello: ClientHello's random + session id ...
        mov esi, SHTAIL
        mov cl, 51
        rep movsb               ; ... + suite, extensions, our key share
        lea eax, [edx+86]
        shl eax, 24
        mov al, 2
        mov [ebx], eax          ; type 2, length

        mov ebp, SLOTS + 128    ; key schedule up to the handshake secret
        push ebx
        mov esi, CVB            ; (ecx = 0 after the copy above)
        lea edi, [ebp+S_EH]
        call sha256             ; SHA256("")
        lea ebx, [ebp+S_Z]
        mov esi, ebx
        mov cl, 32
        lea edi, [ebp+S_ES]
        call hmac               ; early secret
        mov ebx, edi
        mov esi, TR
.ks:    inc esi                 ; the client's x25519 key share: as ours is 9 (the base point),
        cmp dword [esi], 0x20001d00 ; X25519(their key, 9) is that key share itself
        jne .ks
        lodsd
        lea edi, [ebp+S_HS]
        call stage              ; handshake secret
        pop ebx

        mov edi, CVB            ; CertificateVerify content: 64 spaces | context | hash
        mov al, 0x20
        mov cl, 64
        rep stosb
        mov esi, CVCTX
        mov cl, 34
        rep movsb
        ; ECDSA with k=1, d=1/r gives s = z + 1. Grind our server random until s is a plain
        ; 32-byte DER INTEGER (no carry, 0 < s[0] < 0x80): about 2 tries, fixed-size encoding.
.retry: inc byte [ebx+6]
        lea eax, [ebx+edx+90]   ; P1 = end of ServerHello
        call thash
        push ebx
        push edx
        lea ebx, [ebp+S_HS]
        mov esi, L_SHTS
        lea edx, [ebp+S_TH]
        lea edi, [ebp+S_TS]
        call expand             ; server handshake traffic secret
        pop edx
        pop ebx
        xchg eax, edi           ; EncryptedExtensions + Certificate (after thash: it pads in place)
        mov esi, EECERT
        mov ecx, EECERT_LEN
        rep movsb
        xchg eax, edi           ; eax = P2
        call thash
        lea esi, [ebp+S_TH]
        mov edi, CVB+98
        mov cl, 32
        rep movsb
        mov esi, CVB
        mov cl, 130
        lea edi, [eax+46]
        call sha256             ; z, right where s goes in the message
        inc byte [edi+31]
        jz .retry
        cmp byte [edi], 0
        jle .retry
        xchg eax, edi
        mov esi, CVT            ; 0f 00 00 4a | 04 03 | 00 46 | 30 44 02 20 <r> 02 20
        mov cl, 46
        rep movsb
        add edi, 32
        xchg eax, edi           ; eax = P3 = end of CertificateVerify

        mov edi, OB             ; ServerHello record (the random is final now)
        mov dword [edi], 0x00030316
        lea ecx, [edx+90]
        mov [edi+4], cl
        add edi, 5
        mov esi, ebx
        rep movsb
        push esi                ; P1 = end of ServerHello = start of the encrypted part
        push edi                ; output position
        lea ebx, [ebp+S_TS]
        mov edi, KH
        call keys               ; handshake key and iv

        mov esi, L_FIN
        xor edx, edx
        lea edi, [ebp+S_D]
        call expand
        mov ebx, edi            ; finished key
        call thash
        xchg eax, edi
        mov eax, 0x20000014
        stosd
        lea esi, [ebp+S_TH]
        mov cl, 32              ; (ecx = 0 after the copy above)
        call hmac
        add edi, ecx
        mov byte [edi], 0x16    ; inner content type: handshake
        xchg eax, edi

        pop edi                 ; output position
        pop esi                 ; P1
        lea ecx, [eax+1]
        sub ecx, esi
        mov ebx, KH
        xor edx, edx
        call seal               ; edi = end of output

        call thash              ; application traffic secret
        lea ebx, [ebp+S_HS]
        lea esi, [ebp+S_Z]
        push edi
        lea edi, [ebp+S_ES]
        call stage              ; master secret
        mov ebx, edi
        mov esi, L_SATS
        lea edx, [ebp+S_TH]
        lea edi, [ebp+S_TS]
        call expand
        mov ebx, edi
        pop edi
        pop ebp
        push edi
        lea edi, [ebp+C_KIV]
        call keys
        pop edi
        ret

; thash: TH slot = SHA256(transcript up to eax)
thash:
        pushad
        mov esi, TR
        mov ecx, eax
        sub ecx, esi
        lea edi, [ebp+S_TH]
        call sha256
        popad
        ret

; stage: edi = HKDF-Extract(Derive-Secret(ebx, "derived", ""), 32 bytes at esi)
stage:
        pushad
        push esi
        push edi
        mov esi, L_DER
        lea edx, [ebp+S_EH]
        lea edi, [ebp+S_D]
        call expand
        mov ebx, edi
        pop edi
        pop esi
        push 32
        pop ecx
        call hmac
        popad
        ret
%endif

; keys: edi = key(32) | 0(4) | iv(12) from traffic secret ebx (+20 junk bytes: expand writes 32)
keys:
        pushad
        xor edx, edx
        mov esi, L_KEY
        call expand
        add edi, 36
        mov [edi-4], edx        ; block counter 0 (slots near 16 MiB hold SeaBIOS tables)
        add esi, L_IV - L_KEY
        call expand
        popad
        ret

; ----------------------------------------------------------------------------
; sha256: edi = SHA-256 of ecx bytes at esi. Pads in place: esi[ecx .. ecx+72) is clobbered.
sha256:
        pushad
        push edi
        lea edi, [esi+ecx]
        lea eax, [ecx+72]
        and al, 0xC0
        sub eax, ecx            ; padding bytes
        shl ecx, 3
        bswap ecx
        xchg eax, ecx           ; eax = bit length, big-endian
        push eax
        mov al, 0x80
        stosb
        dec ecx
        xor eax, eax
        rep stosb
        pop dword [edi-4]
        push edi                ; end of padded message
        push esi
        mov esi, HT
        mov edi, SH
        mov cl, 8
        rep movsd
        pop esi
.blk:   push esi
        mov esi, SH
        mov edi, AW+256
        mov cl, 8
        rep movsd
        pop esi
        sub edi, 32             ; a..h at [edi]; W[i-k] sits at [edi+32+4k] (window slides down)
        xor ebp, ebp            ; round
.rnd:   call wnext
        mov [edi+32], eax       ; W[i], over the h that the previous round dropped
        add eax, [KT+ebp*4]
        add eax, [edi+28]
        xchg eax, ebx           ; h + k + w
        mov eax, [edi+16]
        mov ecx, 0x190B06       ; S1: ror 6, 11, 25
        call sigma
        add ebx, edx
        mov edx, [edi+20]
        xor edx, [edi+24]
        and edx, eax
        xor edx, [edi+24]       ; ch(e, f, g)
        add ebx, edx            ; t1
        add [edi+12], ebx       ; new e = d + t1
        mov eax, [edi]
        mov ecx, 0x160D02       ; S0: ror 2, 13, 22
        call sigma
        add ebx, edx
        mov edx, [edi+4]
        mov ecx, edx
        or edx, [edi+8]
        and edx, eax
        and ecx, [edi+8]
        or edx, ecx             ; maj(a, b, c)
        add ebx, edx
        sub edi, 4
        mov [edi], ebx          ; new a = t1 + t2
        inc ebp
        cmp ebp, 64
        jne .rnd
        push esi                ; chaining value += a..h
        mov esi, edi
        mov edi, SH
        push 8
        pop ecx
.add:   lodsd
        add [edi], eax
        scasd
        loop .add
        pop esi
        cmp esi, [esp]
        jb .blk
        pop eax
        pop edi
        mov esi, SH
        mov cl, 8
.out:   lodsd
        bswap eax
        stosd
        loop .out
        popad
        ret

; sigma: edx = xor of eax rotated by each count byte in ecx (count | 0x20 = shift instead)
sigma:
        xor edx, edx
.s:     push eax
        test cl, 0x20
        jnz .sh
        ror eax, cl
        jmp .x
.sh:    shr eax, cl
.x:     xor edx, eax
        pop eax
        shr ecx, 8
        jnz .s
        ret

; wnext: eax = message schedule word W[ebp] (window at edi, message at esi)
wnext:  cmp ebp, 16
        jae .sch
        lodsd
        bswap eax
        ret
.sch:   mov eax, [edi+92]       ; W[i-15]
        mov ecx, 0x231207       ; s0: ror 7, ror 18, shr 3
        call sigma
        push edx
        mov eax, [edi+40]       ; W[i-2]
        mov ecx, 0x2A1311       ; s1: ror 17, ror 19, shr 10
        call sigma
        pop eax
        add eax, edx
        add eax, [edi+96]       ; W[i-16]
        add eax, [edi+60]       ; W[i-7]
        ret

; hmac: edi = HMAC-SHA256(key = 32 bytes at ebx, ecx <= 64 bytes at esi)
hmac:
        pushad
        push edi
        push ecx
        mov edi, HB+64
        rep movsb
        mov esi, ebx
        mov edi, HB
        mov cl, 64
.k:     xor eax, eax
        cmp cl, 32
        jbe .z
        lodsb
.z:     xor al, 0x36
        stosb
        loop .k
        pop ecx
        add ecx, 64
        mov esi, HB
        lea edi, [esi+64]
        call sha256             ; inner hash
        mov cl, 64
.o:     xor byte [HB+ecx-1], 0x36 ^ 0x5c
        loop .o
        mov cl, 96
        pop edi
        call sha256             ; outer hash
        popad
        ret

; expand: edi = HKDF-Expand-Label(secret ebx, label esi = {L, len, text}, context edx or 0), 32 bytes
expand:
        pushad
        push edi
        mov edi, INFO
        mov al, 0
        stosb
        movsb                   ; output length
        lodsb
        add al, 6
        stosb
        push esi
        mov esi, TLS13
        movsd
        movsw
        pop esi
        sub al, 6
        movzx ecx, al
        rep movsb
        xor eax, eax
        test edx, edx
        jz .e
        mov al, 32
.e:     stosb
        jz .n
        mov esi, edx
        xchg eax, ecx
        rep movsb
.n:     mov al, 1
        stosb
        lea ecx, [edi-INFO]
        mov esi, INFO
        pop edi
        call hmac
        popad
        ret

; ----------------------------------------------------------------------------
; ----------------------------------------------------------------------------
; chacha: edi = ChaCha20 block of the 16-dword state at esi
chacha:
        pushad
        push esi
        push edi
        push 16
        pop ecx
        rep movsd
        pop ebp                 ; working state
        xor ecx, ecx            ; quarter round 0..79
.qr:    push ecx
        mov eax, ecx
        shl al, 2               ; column * 4 (masked below; al only, so no bit 8 sneaks in)
        and ecx, 4              ; diagonal rounds: shift the column by 4 bytes per row
        mov ebx, ebp
        mov dl, 4
.m:     and al, 12
        lea esi, [ebx+eax]
        push esi
        add eax, ecx
        add ebx, 16
        dec dl
        jnz .m
        pop edi                 ; d
        pop edx                 ; c
        pop ebx                 ; b
        pop esi                 ; a
        mov ecx, 0x07080C10
.st:    mov eax, [ebx]          ; P += Q; R ^= P; R <<<= n; then (P,Q,R) = (other,R,Q)
        add [esi], eax
        mov eax, [esi]
        xor [edi], eax
        rol dword [edi], cl
        xchg esi, edx
        xchg ebx, edi
        shr ecx, 8
        jnz .st
        pop ecx
        inc ecx
        cmp cl, 80
        jne .qr
        pop esi
        mov edi, ebp
        mov cl, 16
.ad:    lodsd
        add [edi], eax
        scasd
        loop .ad
        popad
        ret

; seal: TLS 1.3 record at edi for ecx plaintext bytes at esi (last byte = inner content type),
; key|0|iv at ebx, sequence number edx. Returns edi = end of record.
seal:
        pushad
        push edi                ; o
        push ecx                ; n
        push esi                ; m
        mov edi, ST             ; ChaCha state: constants | key | 0 counter | iv ^ seq
        mov esi, SIGMA
        movsd
        movsd
        movsd
        movsd
        mov esi, ebx
        push 12
        pop ecx
        rep movsd
        bswap edx
        xor [edi-4], edx
        lea esi, [edi-64]       ; ST
        add edi, 64             ; PK = ST + 128
        call chacha             ; block 0: Poly1305 key
        mov edi, SB             ; SB = header, 0 pad | ciphertext, 0 pad | lengths
        mov al, 0x17
        stosb
        mov al, 3
        stosb
        stosb
        mov ecx, [esp+4]
        lea eax, [ecx+16]
        xchg al, ah
        stosw
        add ecx, 42             ; zero a bit more than needed: simpler than rounding
        xor eax, eax
        rep stosb
        pop esi                 ; m
        mov ecx, [esp]          ; n
        mov edi, SB+16
.ks:    push esi
        push edi
        mov esi, ST
        inc dword [esi+48]      ; next counter
        lea edi, [esi+64]       ; KS = ST + 64 (64-byte aligned)
        mov edx, edi
        call chacha
        pop edi
        pop esi
.x:     lodsb
        xor al, [edx]
        inc edx
        stosb
        dec ecx
        jz .d
        test dl, 63
        jnz .x
        jmp .ks
.d:     pop ecx                 ; n
        lea edi, [ecx+SB+16+15]
        and edi, -16            ; SB+16 is 16-aligned
        mov byte [edi], 5       ; aad length
        mov [edi+8], ecx        ; ciphertext length
        lea edx, [edi+16-SB]
        shr edx, 4              ; Poly1305 blocks
        pop edi                 ; o
        mov esi, SB
        movsd                   ; record header
        movsb
        add esi, 11
        rep movsb               ; ciphertext
        mov ebx, PK
        ; Poly1305 tag of the edx 16-byte blocks at SB, key at PK (r is clamped in place).
        ; h has 17 limbs of 8 bits (the top one 2, plus a little), in dwords. With R[16 + j] = r[j] and
        ; R[j - 1] = 320 r[j] (2^136 = 320 mod 2^130 - 5), limb k of h * r = sum_i h[i] * R[16 + k - i].
        push edi                ; where the tag goes
        mov eax, 0x0FFFFFFF
        and [ebx], eax
        mov al, 0xFC
        and [ebx+4], eax
        and [ebx+8], eax
        and [ebx+12], eax
        mov edi, PH
        push 17
        pop ecx
        xor eax, eax
        rep stosd               ; h = 0
        mov esi, ebx
        add edi, 68             ; &R[16]
        mov cl, 16
.r:     lodsb                   ; (R[15] = 320 r[16] and R[32] = r[16] are 0: never written)
        stosd
        imul ebp, eax, 320
        mov [edi-72], ebp
        loop .r
        mov ecx, edx            ; blocks
        mov esi, SB
.blk:   push ecx
        mov edi, PH             ; h += block + 2^128 (eax < 256 here)
        mov cl, 16
.m:     lodsb
        add [edi], eax
        scasd
        loop .m
        inc dword [edi]
        push esi
        mov edi, XT             ; XT = h * r: under 2^30 per limb
        mov ebx, RR + 64
        mov cl, 17
.k:     push ecx
        mov esi, PH
        mov edx, ebx
        xor ebp, ebp
        mov cl, 17
.i:     lodsd
        imul eax, [edx]
        add ebp, eax
        sub edx, 4
        loop .i
        xchg eax, ebp
        stosd
        add ebx, 4
        pop ecx
        loop .k
        xor ebx, ebx            ; carry XT back into h, then twice more in place: 2^130
        mov dl, 3               ; wraps as 5 (the 3rd pass only ripples a carry or two)
        mov esi, XT
.pass:  mov edi, PH
        mov cl, 16
.c:     lodsd
        add ebx, eax
        movzx eax, bl
        sar ebx, 8
        stosd
        loop .c
        lodsd
        add ebx, eax
        mov eax, ebx
        and eax, 3
        stosd                   ; (leaves eax < 4 for the next block's lodsb)
        sar ebx, 2
        lea ebx, [ebx+ebx*4]
        lea esi, [edi-68]
        dec dl
        jnz .pass
        pop esi
        pop ecx
        loop .blk
        pop edi
        mov ebx, PK+16
        mov esi, PH
        mov cl, 16
        xor edx, edx
.t:     lodsd                   ; tag = h + s mod 2^128
        add edx, eax
        movzx eax, byte [ebx]
        inc ebx
        add edx, eax
        mov [edi], dl
        inc edi
        shr edx, 8
        loop .t
        mov [esp], edi
        popad
        ret


; ----------------------------------------------------------------------------

TWO32:  dd 0x4F800000            ; 2^32 as a float

L_DER:  db 32, 7, "derived"
L_SHTS: db 32, 12, "s hs traffic"
L_SATS: db 32, 12, "s ap traffic"
L_FIN:  db 32, 8, "finished"
L_KEY:  db 32, 3, "key"
L_IV:   db 12, 2, "iv"
TLS13:  db "tls13 "
SIGMA:  db "expand 32-byte k"

%ifndef HOST
CVCTX:  db "TLS 1.3, server CertificateVerify", 0
nicinit: db 1, 0x46, 2, 0xC0, 4, 0x40, 12, 0x10, 0, 0x40, 7, 0x46, 0, 0
%include "build/gen.inc"
SHTAIL: db 0x13, 0x03, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
        db 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20
PUB:    db 9                    ; base point; 31 zero bytes follow via bss_end (keep this last)
%endif
