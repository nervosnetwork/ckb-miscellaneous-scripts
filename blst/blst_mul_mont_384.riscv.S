.text
# .globl    blst_mul_mont_384
# special directive: ['.globl', 'blst_mul_mont_384']
# blst_mul_mont_384:    
.globl    blst_mul_mont_384
.align    4
blst_mul_mont_384:
addi sp, sp, -8
sd ra, 0(sp)
# .byte    0xf3, 0x0f, 0x1e, 0xfa
# special directive: ['.byte', '0xf3', '0x0f', '0x1e', '0xfa']
# pushq    %rbp
# pushq %rbp
# pushq %rbx
# pushq %r12
# pushq %r13
# pushq %r14
# pushq %r15
addi    sp, sp, -48
sd fp, 40(sp)
sd s1, 32(sp)
sd s2, 24(sp)
sd s3, 16(sp)
sd s4, 8(sp)
sd s5, 0(sp)
addi    sp, sp, -24
# movq    0(%rdx), %rax
ld    a6, 0(a2)
# movq    0(%rsi), %r14
ld    s4, 0(a1)
# movq    8(%rsi), %r15
ld    s5, 8(a1)
# movq    16(%rsi), %r12
ld    s2, 16(a1)
# movq    24(%rsi), %r13
ld    s3, 24(a1)
# movq    %rdx, %rbx
add    s1, a2, zero
# movq    %r8, 0(%rsp)
sd    a4, 0(sp)
# movq    %rdi, 8(%rsp)
sd    a0, 8(sp)
# call    __blst_mulq_mont_384
call    __blst_mulq_mont_384
# movq    24(%rsp), %r15
ld    s5, 24(sp)
# movq    32(%rsp), %r14
ld    s4, 32(sp)
# movq    40(%rsp), %r13
ld    s3, 40(sp)
# movq    48(%rsp), %r12
ld    s2, 48(sp)
# movq    56(%rsp), %rbx
ld    s1, 56(sp)
# movq    64(%rsp), %rbp
ld    fp, 64(sp)
# leaq    72(%rsp), %rsp
addi    sp, sp, 72
# .byte    0xf3, 0xc3
ld ra, 0(sp)
addi sp, sp, 8
ret    
# __blst_mulq_mont_384:    
.globl    __blst_mulq_mont_384
.align    4
__blst_mulq_mont_384:
addi sp, sp, -8
sd ra, 0(sp)
# .byte    0xf3, 0x0f, 0x1e, 0xfa
# special directive: ['.byte', '0xf3', '0x0f', '0x1e', '0xfa']
# movq    %rax, %rdi
add    a0, a6, zero
# mulq    %r14
mulhu    a2, s4, a6
mul    a6, s4, a6
# movq    %rax, %r8
add    a4, a6, zero
# movq    %rdi, %rax
add    a6, a0, zero
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    %r15
mulhu    a2, s5, a6
mul    a6, s5, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    %r12
mulhu    a2, s2, a6
mul    a6, s2, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# movq    %r8, %rbp
add    fp, a4, zero
# imulq    8(%rsp), %r8
ld    t6, 8(sp)
mul    a4, a4, t6
# mulq    %r13
mulhu    a2, s3, a6
mul    a6, s3, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r13
add    s3, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# xorq    %r15, %r15
xor    s5, s5, s5
# movq    %rdx, %r14
add    s4, a2, zero
# mulq    0(%rcx)
ld    t6, 0(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rbp
add    fp, fp, a6
sltu    t2, fp, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    %rdx, %rbp
add    fp, fp, t2
sltu    t2, fp, t2
add    fp, fp, a2
sltu    a2, fp, a2
or    t2, t2, a2
# mulq    8(%rcx)
ld    t6, 8(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r9
add    a5, a5, fp
sltu    t2, a5, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    16(%rcx)
ld    t6, 16(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r10
add    t0, t0, fp
sltu    t2, t0, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    24(%rcx)
ld    t6, 24(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rbp, %r11
add    t1, t1, fp
sltu    t2, t1, fp
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    32(%rcx)
ld    t6, 32(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r12
add    s2, s2, fp
sltu    t2, s2, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    40(%rcx)
ld    t6, 40(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    8(%rbx), %rax
ld    a6, 8(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r13
add    s3, s3, fp
sltu    t2, s3, fp
# adcq    %rdx, %r14
add    s4, s4, t2
sltu    t2, s4, t2
add    s4, s4, a2
sltu    a2, s4, a2
or    t2, t2, a2
# adcq    $0, %r15
add    s5, t2, s5
# movq    %rax, %rdi
add    a0, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %r10
add    t0, t0, a4
sltu    t2, t0, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %r11
add    t1, t1, a4
sltu    t2, t1, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# movq    %r9, %rbp
add    fp, a5, zero
# imulq    8(%rsp), %r9
ld    t6, 8(sp)
mul    a5, a5, t6
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %r12
add    s2, s2, a4
sltu    t2, s2, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %r13
add    s3, s3, a4
sltu    t2, s3, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %r8, %r14
add    s4, s4, a4
sltu    t2, s4, a4
# adcq    $0, %rdx
add    a2, t2, a2
# xorq    %r8, %r8
xor    a4, a4, a4
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    %rdx, %r15
add    s5, s5, t2
sltu    t2, s5, t2
add    s5, s5, a2
sltu    a2, s5, a2
or    t2, t2, a2
# adcq    $0, %r8
add    a4, t2, a4
# mulq    0(%rcx)
ld    t6, 0(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rbp
add    fp, fp, a6
sltu    t2, fp, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    %rdx, %rbp
add    fp, fp, t2
sltu    t2, fp, t2
add    fp, fp, a2
sltu    a2, fp, a2
or    t2, t2, a2
# mulq    8(%rcx)
ld    t6, 8(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r10
add    t0, t0, fp
sltu    t2, t0, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    16(%rcx)
ld    t6, 16(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r11
add    t1, t1, fp
sltu    t2, t1, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    24(%rcx)
ld    t6, 24(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rbp, %r12
add    s2, s2, fp
sltu    t2, s2, fp
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    32(%rcx)
ld    t6, 32(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r13
add    s3, s3, fp
sltu    t2, s3, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    40(%rcx)
ld    t6, 40(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    16(%rbx), %rax
ld    a6, 16(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r14
add    s4, s4, fp
sltu    t2, s4, fp
# adcq    %rdx, %r15
add    s5, s5, t2
sltu    t2, s5, t2
add    s5, s5, a2
sltu    a2, s5, a2
or    t2, t2, a2
# adcq    $0, %r8
add    a4, t2, a4
# movq    %rax, %rdi
add    a0, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r11
add    t1, t1, a5
sltu    t2, t1, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r12
add    s2, s2, a5
sltu    t2, s2, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# movq    %r10, %rbp
add    fp, t0, zero
# imulq    8(%rsp), %r10
ld    t6, 8(sp)
mul    t0, t0, t6
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r13
add    s3, s3, a5
sltu    t2, s3, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r14
add    s4, s4, a5
sltu    t2, s4, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %r9, %r15
add    s5, s5, a5
sltu    t2, s5, a5
# adcq    $0, %rdx
add    a2, t2, a2
# xorq    %r9, %r9
xor    a5, a5, a5
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    %rdx, %r8
add    a4, a4, t2
sltu    t2, a4, t2
add    a4, a4, a2
sltu    a2, a4, a2
or    t2, t2, a2
# adcq    $0, %r9
add    a5, t2, a5
# mulq    0(%rcx)
ld    t6, 0(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rbp
add    fp, fp, a6
sltu    t2, fp, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    %rdx, %rbp
add    fp, fp, t2
sltu    t2, fp, t2
add    fp, fp, a2
sltu    a2, fp, a2
or    t2, t2, a2
# mulq    8(%rcx)
ld    t6, 8(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r11
add    t1, t1, fp
sltu    t2, t1, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    16(%rcx)
ld    t6, 16(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r12
add    s2, s2, fp
sltu    t2, s2, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    24(%rcx)
ld    t6, 24(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rbp, %r13
add    s3, s3, fp
sltu    t2, s3, fp
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    32(%rcx)
ld    t6, 32(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r14
add    s4, s4, fp
sltu    t2, s4, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    40(%rcx)
ld    t6, 40(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    24(%rbx), %rax
ld    a6, 24(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r15
add    s5, s5, fp
sltu    t2, s5, fp
# adcq    %rdx, %r8
add    a4, a4, t2
sltu    t2, a4, t2
add    a4, a4, a2
sltu    a2, a4, a2
or    t2, t2, a2
# adcq    $0, %r9
add    a5, t2, a5
# movq    %rax, %rdi
add    a0, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r12
add    s2, s2, t0
sltu    t2, s2, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r13
add    s3, s3, t0
sltu    t2, s3, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# movq    %r11, %rbp
add    fp, t1, zero
# imulq    8(%rsp), %r11
ld    t6, 8(sp)
mul    t1, t1, t6
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r14
add    s4, s4, t0
sltu    t2, s4, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r15
add    s5, s5, t0
sltu    t2, s5, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %r10, %r8
add    a4, a4, t0
sltu    t2, a4, t0
# adcq    $0, %rdx
add    a2, t2, a2
# xorq    %r10, %r10
xor    t0, t0, t0
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    %rdx, %r9
add    a5, a5, t2
sltu    t2, a5, t2
add    a5, a5, a2
sltu    a2, a5, a2
or    t2, t2, a2
# adcq    $0, %r10
add    t0, t2, t0
# mulq    0(%rcx)
ld    t6, 0(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rbp
add    fp, fp, a6
sltu    t2, fp, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    %rdx, %rbp
add    fp, fp, t2
sltu    t2, fp, t2
add    fp, fp, a2
sltu    a2, fp, a2
or    t2, t2, a2
# mulq    8(%rcx)
ld    t6, 8(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r12
add    s2, s2, fp
sltu    t2, s2, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    16(%rcx)
ld    t6, 16(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r13
add    s3, s3, fp
sltu    t2, s3, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    24(%rcx)
ld    t6, 24(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rbp, %r14
add    s4, s4, fp
sltu    t2, s4, fp
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    32(%rcx)
ld    t6, 32(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r15
add    s5, s5, fp
sltu    t2, s5, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    40(%rcx)
ld    t6, 40(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    32(%rbx), %rax
ld    a6, 32(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r8
add    a4, a4, fp
sltu    t2, a4, fp
# adcq    %rdx, %r9
add    a5, a5, t2
sltu    t2, a5, t2
add    a5, a5, a2
sltu    a2, a5, a2
or    t2, t2, a2
# adcq    $0, %r10
add    t0, t2, t0
# movq    %rax, %rdi
add    a0, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r13
add    s3, s3, t1
sltu    t2, s3, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r14
add    s4, s4, t1
sltu    t2, s4, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# movq    %r12, %rbp
add    fp, s2, zero
# imulq    8(%rsp), %r12
ld    t6, 8(sp)
mul    s2, s2, t6
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r15
add    s5, s5, t1
sltu    t2, s5, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r8
add    a4, a4, t1
sltu    t2, a4, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %r11, %r9
add    a5, a5, t1
sltu    t2, a5, t1
# adcq    $0, %rdx
add    a2, t2, a2
# xorq    %r11, %r11
xor    t1, t1, t1
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    %rdx, %r10
add    t0, t0, t2
sltu    t2, t0, t2
add    t0, t0, a2
sltu    a2, t0, a2
or    t2, t2, a2
# adcq    $0, %r11
add    t1, t2, t1
# mulq    0(%rcx)
ld    t6, 0(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rbp
add    fp, fp, a6
sltu    t2, fp, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    %rdx, %rbp
add    fp, fp, t2
sltu    t2, fp, t2
add    fp, fp, a2
sltu    a2, fp, a2
or    t2, t2, a2
# mulq    8(%rcx)
ld    t6, 8(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r13
add    s3, s3, fp
sltu    t2, s3, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    16(%rcx)
ld    t6, 16(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r14
add    s4, s4, fp
sltu    t2, s4, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    24(%rcx)
ld    t6, 24(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rbp, %r15
add    s5, s5, fp
sltu    t2, s5, fp
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    32(%rcx)
ld    t6, 32(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r8
add    a4, a4, fp
sltu    t2, a4, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    40(%rcx)
ld    t6, 40(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    40(%rbx), %rax
ld    a6, 40(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r9
add    a5, a5, fp
sltu    t2, a5, fp
# adcq    %rdx, %r10
add    t0, t0, t2
sltu    t2, t0, t2
add    t0, t0, a2
sltu    a2, t0, a2
or    t2, t2, a2
# adcq    $0, %r11
add    t1, t2, t1
# movq    %rax, %rdi
add    a0, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r12, %r14
add    s4, s4, s2
sltu    t2, s4, s2
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r12, %r15
add    s5, s5, s2
sltu    t2, s5, s2
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# movq    %r13, %rbp
add    fp, s3, zero
# imulq    8(%rsp), %r13
ld    t6, 8(sp)
mul    s3, s3, t6
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r12, %r8
add    a4, a4, s2
sltu    t2, a4, s2
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %rdi, %rax
add    a6, a0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r12, %r9
add    a5, a5, s2
sltu    t2, a5, s2
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %r12, %r10
add    t0, t0, s2
sltu    t2, t0, s2
# adcq    $0, %rdx
add    a2, t2, a2
# xorq    %r12, %r12
xor    s2, s2, s2
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    %rdx, %r11
add    t1, t1, t2
sltu    t2, t1, t2
add    t1, t1, a2
sltu    a2, t1, a2
or    t2, t2, a2
# adcq    $0, %r12
add    s2, t2, s2
# mulq    0(%rcx)
ld    t6, 0(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rbp
add    fp, fp, a6
sltu    t2, fp, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    %rdx, %rbp
add    fp, fp, t2
sltu    t2, fp, t2
add    fp, fp, a2
sltu    a2, fp, a2
or    t2, t2, a2
# mulq    8(%rcx)
ld    t6, 8(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r14
add    s4, s4, fp
sltu    t2, s4, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    16(%rcx)
ld    t6, 16(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r15
add    s5, s5, fp
sltu    t2, s5, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    24(%rcx)
ld    t6, 24(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rbp, %r8
add    a4, a4, fp
sltu    t2, a4, fp
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    32(%rcx)
ld    t6, 32(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r9
add    a5, a5, fp
sltu    t2, a5, fp
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %rbp
add    fp, a2, zero
# mulq    40(%rcx)
ld    t6, 40(a3)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %r14, %rax
add    a6, s4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %rbp, %r10
add    t0, t0, fp
sltu    t2, t0, fp
# adcq    %rdx, %r11
add    t1, t1, t2
sltu    t2, t1, t2
add    t1, t1, a2
sltu    a2, t1, a2
or    t2, t2, a2
# adcq    $0, %r12
add    s2, t2, s2
# movq    16(%rsp), %rdi
ld    a0, 16(sp)
# subq    0(%rcx), %r14
ld    t6, 0(a3)
sltu    t2, s4, t6
sub    s4, s4, t6
# movq    %r15, %rdx
add    a2, s5, zero
# sbbq    8(%rcx), %r15
ld    t6, 8(a3)
sub    t2, s5, t2
sltu    a7, s5, t2
sub    s5, t2, t6
sltu    t6, t2, s5
or    t2, t6, a7
# movq    %r8, %rbx
add    s1, a4, zero
# sbbq    16(%rcx), %r8
ld    t6, 16(a3)
sub    t2, a4, t2
sltu    a7, a4, t2
sub    a4, t2, t6
sltu    t6, t2, a4
or    t2, t6, a7
# movq    %r9, %rsi
add    a1, a5, zero
# sbbq    24(%rcx), %r9
ld    t6, 24(a3)
sub    t2, a5, t2
sltu    a7, a5, t2
sub    a5, t2, t6
sltu    t6, t2, a5
or    t2, t6, a7
# movq    %r10, %rbp
add    fp, t0, zero
# sbbq    32(%rcx), %r10
ld    t6, 32(a3)
sub    t2, t0, t2
sltu    a7, t0, t2
sub    t0, t2, t6
sltu    t6, t2, t0
or    t2, t6, a7
# movq    %r11, %r13
add    s3, t1, zero
# sbbq    40(%rcx), %r11
ld    t6, 40(a3)
sub    t2, t1, t2
sltu    a7, t1, t2
sub    t1, t2, t6
sltu    t6, t2, t1
or    t2, t6, a7
# sbbq    $0, %r12
sltu    a7, s2, t2
sub    s2, s2, t2
add    t2, a7, zero
# cmovcq    %rax, %r14
beq    t2, zero, .LABLE1
add    s4, a6, zero
.LABLE1:
# cmovcq    %rdx, %r15
beq    t2, zero, .LABLE2
add    s5, a2, zero
.LABLE2:
# cmovcq    %rbx, %r8
beq    t2, zero, .LABLE3
add    a4, s1, zero
.LABLE3:
# movq    %r14, 0(%rdi)
sd    s4, 0(a0)
# cmovcq    %rsi, %r9
beq    t2, zero, .LABLE4
add    a5, a1, zero
.LABLE4:
# movq    %r15, 8(%rdi)
sd    s5, 8(a0)
# cmovcq    %rbp, %r10
beq    t2, zero, .LABLE5
add    t0, fp, zero
.LABLE5:
# movq    %r8, 16(%rdi)
sd    a4, 16(a0)
# cmovcq    %r13, %r11
beq    t2, zero, .LABLE6
add    t1, s3, zero
.LABLE6:
# movq    %r9, 24(%rdi)
sd    a5, 24(a0)
# movq    %r10, 32(%rdi)
sd    t0, 32(a0)
# movq    %r11, 40(%rdi)
sd    t1, 40(a0)
# .byte    0xf3, 0xc3
ld ra, 0(sp)
addi sp, sp, 8
ret    
