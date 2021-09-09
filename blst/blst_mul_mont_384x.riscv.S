.text
# .globl    blst_mul_mont_384x
# special directive: ['.globl', 'blst_mul_mont_384x']
# blst_mul_mont_384x:    
.globl    blst_mul_mont_384x
.align    4
blst_mul_mont_384x:
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
addi    sp, sp, -328
# movq    %rdx, %rbx
add    s1, a2, zero
# movq    %rdi, 32(%rsp)
sd    a0, 32(sp)
# movq    %rsi, 24(%rsp)
sd    a1, 24(sp)
# movq    %rdx, 16(%rsp)
sd    a2, 16(sp)
# movq    %rcx, 8(%rsp)
sd    a3, 8(sp)
# movq    %r8, 0(%rsp)
sd    a4, 0(sp)
# leaq    40(%rsp), %rdi
addi    a0, sp, 40
# call    __blst_mulq_384
call    __blst_mulq_384
# leaq    48(%rbx), %rbx
addi    s1, s1, 48
# leaq    48(%rsi), %rsi
addi    a1, a1, 48
# leaq    40+96(%rsp), %rdi
addi    a0, sp, 136
# call    __blst_mulq_384
call    __blst_mulq_384
# movq    8(%rsp), %rcx
ld    a3, 8(sp)
# leaq    -48(%rsi), %rdx
addi    a2, a1, -48
# leaq    40+192+48(%rsp), %rdi
addi    a0, sp, 280
# call    __blst_add_mod_384
call    __blst_add_mod_384
# movq    16(%rsp), %rsi
ld    a1, 16(sp)
# leaq    48(%rsi), %rdx
addi    a2, a1, 48
# leaq    -48(%rdi), %rdi
addi    a0, a0, -48
# call    __blst_add_mod_384
call    __blst_add_mod_384
# leaq    (%rdi), %rbx
addi    s1, a0, 0
# leaq    48(%rdi), %rsi
addi    a1, a0, 48
# call    __blst_mulq_384
call    __blst_mulq_384
# leaq    (%rdi), %rsi
addi    a1, a0, 0
# leaq    40(%rsp), %rdx
addi    a2, sp, 40
# movq    8(%rsp), %rcx
ld    a3, 8(sp)
# call    __blst_sub_mod_384x384
call    __blst_sub_mod_384x384
# leaq    (%rdi), %rsi
addi    a1, a0, 0
# leaq    -96(%rdi), %rdx
addi    a2, a0, -96
# call    __blst_sub_mod_384x384
call    __blst_sub_mod_384x384
# leaq    40(%rsp), %rsi
addi    a1, sp, 40
# leaq    40+96(%rsp), %rdx
addi    a2, sp, 136
# leaq    40(%rsp), %rdi
addi    a0, sp, 40
# call    __blst_sub_mod_384x384
call    __blst_sub_mod_384x384
# movq    %rcx, %rbx
add    s1, a3, zero
# leaq    40(%rsp), %rsi
addi    a1, sp, 40
# movq    0(%rsp), %rcx
ld    a3, 0(sp)
# movq    32(%rsp), %rdi
ld    a0, 32(sp)
# call    __blst_mulq_by_1_mont_384
call    __blst_mulq_by_1_mont_384
# call    __blst_redc_tail_mont_384
call    __blst_redc_tail_mont_384
# leaq    40+192(%rsp), %rsi
addi    a1, sp, 232
# movq    0(%rsp), %rcx
ld    a3, 0(sp)
# leaq    48(%rdi), %rdi
addi    a0, a0, 48
# call    __blst_mulq_by_1_mont_384
call    __blst_mulq_by_1_mont_384
# call    __blst_redc_tail_mont_384
call    __blst_redc_tail_mont_384
# leaq    328(%rsp), %r8
addi    a4, sp, 328
# movq    0(%r8), %r15
ld    s5, 0(a4)
# movq    8(%r8), %r14
ld    s4, 8(a4)
# movq    16(%r8), %r13
ld    s3, 16(a4)
# movq    24(%r8), %r12
ld    s2, 24(a4)
# movq    32(%r8), %rbx
ld    s1, 32(a4)
# movq    40(%r8), %rbp
ld    fp, 40(a4)
# leaq    48(%r8), %rsp
addi    sp, a4, 48
# .byte    0xf3, 0xc3
ld ra, 0(sp)
addi sp, sp, 8
ret    
# __blst_mulq_384:    
.globl    __blst_mulq_384
.align    4
__blst_mulq_384:
addi sp, sp, -8
sd ra, 0(sp)
# movq    0(%rbx), %rax
ld    a6, 0(s1)
# movq    %rax, %rbp
add    fp, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# movq    %rax, 0(%rdi)
sd    a6, 0(a0)
# movq    %rbp, %rax
add    a6, fp, zero
# movq    %rdx, %rcx
add    a3, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rcx
add    a3, a3, a6
sltu    t2, a3, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    8(%rbx), %rax
ld    a6, 8(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# movq    %rax, %rbp
add    fp, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rcx
add    a3, a3, a6
sltu    t2, a3, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rcx, 8(%rdi)
sd    a3, 8(a0)
# movq    %rdx, %rcx
add    a3, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %rcx
add    a3, a3, a4
sltu    t2, a3, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r8
add    a4, a4, a5
sltu    t2, a4, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r9
add    a5, a5, t0
sltu    t2, a5, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r10
add    t0, t0, t1
sltu    t2, t0, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    16(%rbx), %rax
ld    a6, 16(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r12, %r11
add    t1, t1, s2
sltu    t2, t1, s2
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# movq    %rax, %rbp
add    fp, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rcx
add    a3, a3, a6
sltu    t2, a3, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rcx, 16(%rdi)
sd    a3, 16(a0)
# movq    %rdx, %rcx
add    a3, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %rcx
add    a3, a3, a4
sltu    t2, a3, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r8
add    a4, a4, a5
sltu    t2, a4, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r9
add    a5, a5, t0
sltu    t2, a5, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r10
add    t0, t0, t1
sltu    t2, t0, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    24(%rbx), %rax
ld    a6, 24(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r12, %r11
add    t1, t1, s2
sltu    t2, t1, s2
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# movq    %rax, %rbp
add    fp, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rcx
add    a3, a3, a6
sltu    t2, a3, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rcx, 24(%rdi)
sd    a3, 24(a0)
# movq    %rdx, %rcx
add    a3, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %rcx
add    a3, a3, a4
sltu    t2, a3, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r8
add    a4, a4, a5
sltu    t2, a4, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r9
add    a5, a5, t0
sltu    t2, a5, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r10
add    t0, t0, t1
sltu    t2, t0, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    32(%rbx), %rax
ld    a6, 32(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r12, %r11
add    t1, t1, s2
sltu    t2, t1, s2
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# movq    %rax, %rbp
add    fp, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rcx
add    a3, a3, a6
sltu    t2, a3, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rcx, 32(%rdi)
sd    a3, 32(a0)
# movq    %rdx, %rcx
add    a3, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %rcx
add    a3, a3, a4
sltu    t2, a3, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r8
add    a4, a4, a5
sltu    t2, a4, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r9
add    a5, a5, t0
sltu    t2, a5, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r10
add    t0, t0, t1
sltu    t2, t0, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    40(%rbx), %rax
ld    a6, 40(s1)
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r12, %r11
add    t1, t1, s2
sltu    t2, t1, s2
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# movq    %rax, %rbp
add    fp, a6, zero
# mulq    0(%rsi)
ld    t6, 0(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %rcx
add    a3, a3, a6
sltu    t2, a3, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rcx, 40(%rdi)
sd    a3, 40(a0)
# movq    %rdx, %rcx
add    a3, a2, zero
# mulq    8(%rsi)
ld    t6, 8(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %rcx
add    a3, a3, a4
sltu    t2, a3, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    16(%rsi)
ld    t6, 16(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r8
add    a4, a4, a5
sltu    t2, a4, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    24(%rsi)
ld    t6, 24(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r9
add    a5, a5, t0
sltu    t2, a5, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    32(%rsi)
ld    t6, 32(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %rbp, %rax
add    a6, fp, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r10
add    t0, t0, t1
sltu    t2, t0, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    40(%rsi)
ld    t6, 40(a1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %rax, %rax
add    a6, a6, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r12, %r11
add    t1, t1, s2
sltu    t2, t1, s2
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r12
add    s2, a2, zero
# movq    %rcx, 48(%rdi)
sd    a3, 48(a0)
# movq    %r8, 56(%rdi)
sd    a4, 56(a0)
# movq    %r9, 64(%rdi)
sd    a5, 64(a0)
# movq    %r10, 72(%rdi)
sd    t0, 72(a0)
# movq    %r11, 80(%rdi)
sd    t1, 80(a0)
# movq    %r12, 88(%rdi)
sd    s2, 88(a0)
# .byte    0xf3, 0xc3
ld ra, 0(sp)
addi sp, sp, 8
ret    
# __blst_add_mod_384:    
.globl    __blst_add_mod_384
.align    4
__blst_add_mod_384:
addi sp, sp, -8
sd ra, 0(sp)
# movq    0(%rsi), %r8
ld    a4, 0(a1)
# movq    8(%rsi), %r9
ld    a5, 8(a1)
# movq    16(%rsi), %r10
ld    t0, 16(a1)
# movq    24(%rsi), %r11
ld    t1, 24(a1)
# movq    32(%rsi), %r12
ld    s2, 32(a1)
# movq    40(%rsi), %r13
ld    s3, 40(a1)
# addq    0(%rdx), %r8
ld    t6, 0(a2)
add    a4, t6, a4
sltu    t2, a4, t6
# adcq    8(%rdx), %r9
ld    t6, 8(a2)
add    a5, a5, t2
sltu    t2, a5, t2
add    a5, a5, t6
sltu    t6, a5, t6
or    t2, t2, t6
# adcq    16(%rdx), %r10
ld    t6, 16(a2)
add    t0, t0, t2
sltu    t2, t0, t2
add    t0, t0, t6
sltu    t6, t0, t6
or    t2, t2, t6
# movq    %r8, %r14
add    s4, a4, zero
# adcq    24(%rdx), %r11
ld    t6, 24(a2)
add    t1, t1, t2
sltu    t2, t1, t2
add    t1, t1, t6
sltu    t6, t1, t6
or    t2, t2, t6
# movq    %r9, %r15
add    s5, a5, zero
# adcq    32(%rdx), %r12
ld    t6, 32(a2)
add    s2, s2, t2
sltu    t2, s2, t2
add    s2, s2, t6
sltu    t6, s2, t6
or    t2, t2, t6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    40(%rdx), %r13
ld    t6, 40(a2)
add    s3, s3, t2
sltu    t2, s3, t2
add    s3, s3, t6
sltu    t6, s3, t6
or    t2, t2, t6
# movq    %r11, %rbx
add    s1, t1, zero
# sbbq    %rdx, %rdx
sub    a2, zero, t2
# subq    0(%rcx), %r8
ld    t6, 0(a3)
sltu    t2, a4, t6
sub    a4, a4, t6
# sbbq    8(%rcx), %r9
ld    t6, 8(a3)
sub    t2, a5, t2
sltu    a7, a5, t2
sub    a5, t2, t6
sltu    t6, t2, a5
or    t2, t6, a7
# movq    %r12, %rbp
add    fp, s2, zero
# sbbq    16(%rcx), %r10
ld    t6, 16(a3)
sub    t2, t0, t2
sltu    a7, t0, t2
sub    t0, t2, t6
sltu    t6, t2, t0
or    t2, t6, a7
# sbbq    24(%rcx), %r11
ld    t6, 24(a3)
sub    t2, t1, t2
sltu    a7, t1, t2
sub    t1, t2, t6
sltu    t6, t2, t1
or    t2, t6, a7
# sbbq    32(%rcx), %r12
ld    t6, 32(a3)
sub    t2, s2, t2
sltu    a7, s2, t2
sub    s2, t2, t6
sltu    t6, t2, s2
or    t2, t6, a7
# movq    %r13, %rsi
add    a1, s3, zero
# sbbq    40(%rcx), %r13
ld    t6, 40(a3)
sub    t2, s3, t2
sltu    a7, s3, t2
sub    s3, t2, t6
sltu    t6, t2, s3
or    t2, t6, a7
# sbbq    $0, %rdx
sltu    a7, a2, t2
sub    a2, a2, t2
add    t2, a7, zero
# cmovcq    %r14, %r8
beq    t2, zero, .LABLE1
add    a4, s4, zero
.LABLE1:
# cmovcq    %r15, %r9
beq    t2, zero, .LABLE2
add    a5, s5, zero
.LABLE2:
# cmovcq    %rax, %r10
beq    t2, zero, .LABLE3
add    t0, a6, zero
.LABLE3:
# movq    %r8, 0(%rdi)
sd    a4, 0(a0)
# cmovcq    %rbx, %r11
beq    t2, zero, .LABLE4
add    t1, s1, zero
.LABLE4:
# movq    %r9, 8(%rdi)
sd    a5, 8(a0)
# cmovcq    %rbp, %r12
beq    t2, zero, .LABLE5
add    s2, fp, zero
.LABLE5:
# movq    %r10, 16(%rdi)
sd    t0, 16(a0)
# cmovcq    %rsi, %r13
beq    t2, zero, .LABLE6
add    s3, a1, zero
.LABLE6:
# movq    %r11, 24(%rdi)
sd    t1, 24(a0)
# movq    %r12, 32(%rdi)
sd    s2, 32(a0)
# movq    %r13, 40(%rdi)
sd    s3, 40(a0)
# .byte    0xf3, 0xc3
ld ra, 0(sp)
addi sp, sp, 8
ret    
# __blst_sub_mod_384x384:    
.globl    __blst_sub_mod_384x384
.align    4
__blst_sub_mod_384x384:
addi sp, sp, -8
sd ra, 0(sp)
# .byte    0xf3, 0x0f, 0x1e, 0xfa
# special directive: ['.byte', '0xf3', '0x0f', '0x1e', '0xfa']
# movq    0(%rsi), %r8
ld    a4, 0(a1)
# movq    8(%rsi), %r9
ld    a5, 8(a1)
# movq    16(%rsi), %r10
ld    t0, 16(a1)
# movq    24(%rsi), %r11
ld    t1, 24(a1)
# movq    32(%rsi), %r12
ld    s2, 32(a1)
# movq    40(%rsi), %r13
ld    s3, 40(a1)
# movq    48(%rsi), %r14
ld    s4, 48(a1)
# subq    0(%rdx), %r8
ld    t6, 0(a2)
sltu    t2, a4, t6
sub    a4, a4, t6
# movq    56(%rsi), %r15
ld    s5, 56(a1)
# sbbq    8(%rdx), %r9
ld    t6, 8(a2)
sub    t2, a5, t2
sltu    a7, a5, t2
sub    a5, t2, t6
sltu    t6, t2, a5
or    t2, t6, a7
# movq    64(%rsi), %rax
ld    a6, 64(a1)
# sbbq    16(%rdx), %r10
ld    t6, 16(a2)
sub    t2, t0, t2
sltu    a7, t0, t2
sub    t0, t2, t6
sltu    t6, t2, t0
or    t2, t6, a7
# movq    72(%rsi), %rbx
ld    s1, 72(a1)
# sbbq    24(%rdx), %r11
ld    t6, 24(a2)
sub    t2, t1, t2
sltu    a7, t1, t2
sub    t1, t2, t6
sltu    t6, t2, t1
or    t2, t6, a7
# movq    80(%rsi), %rbp
ld    fp, 80(a1)
# sbbq    32(%rdx), %r12
ld    t6, 32(a2)
sub    t2, s2, t2
sltu    a7, s2, t2
sub    s2, t2, t6
sltu    t6, t2, s2
or    t2, t6, a7
# movq    88(%rsi), %rsi
ld    a1, 88(a1)
# sbbq    40(%rdx), %r13
ld    t6, 40(a2)
sub    t2, s3, t2
sltu    a7, s3, t2
sub    s3, t2, t6
sltu    t6, t2, s3
or    t2, t6, a7
# movq    %r8, 0(%rdi)
sd    a4, 0(a0)
# sbbq    48(%rdx), %r14
ld    t6, 48(a2)
sub    t2, s4, t2
sltu    a7, s4, t2
sub    s4, t2, t6
sltu    t6, t2, s4
or    t2, t6, a7
# movq    0(%rcx), %r8
ld    a4, 0(a3)
# movq    %r9, 8(%rdi)
sd    a5, 8(a0)
# sbbq    56(%rdx), %r15
ld    t6, 56(a2)
sub    t2, s5, t2
sltu    a7, s5, t2
sub    s5, t2, t6
sltu    t6, t2, s5
or    t2, t6, a7
# movq    8(%rcx), %r9
ld    a5, 8(a3)
# movq    %r10, 16(%rdi)
sd    t0, 16(a0)
# sbbq    64(%rdx), %rax
ld    t6, 64(a2)
sub    t2, a6, t2
sltu    a7, a6, t2
sub    a6, t2, t6
sltu    t6, t2, a6
or    t2, t6, a7
# movq    16(%rcx), %r10
ld    t0, 16(a3)
# movq    %r11, 24(%rdi)
sd    t1, 24(a0)
# sbbq    72(%rdx), %rbx
ld    t6, 72(a2)
sub    t2, s1, t2
sltu    a7, s1, t2
sub    s1, t2, t6
sltu    t6, t2, s1
or    t2, t6, a7
# movq    24(%rcx), %r11
ld    t1, 24(a3)
# movq    %r12, 32(%rdi)
sd    s2, 32(a0)
# sbbq    80(%rdx), %rbp
ld    t6, 80(a2)
sub    t2, fp, t2
sltu    a7, fp, t2
sub    fp, t2, t6
sltu    t6, t2, fp
or    t2, t6, a7
# movq    32(%rcx), %r12
ld    s2, 32(a3)
# movq    %r13, 40(%rdi)
sd    s3, 40(a0)
# sbbq    88(%rdx), %rsi
ld    t6, 88(a2)
sub    t2, a1, t2
sltu    a7, a1, t2
sub    a1, t2, t6
sltu    t6, t2, a1
or    t2, t6, a7
# movq    40(%rcx), %r13
ld    s3, 40(a3)
# sbbq    %rdx, %rdx
sub    a2, zero, t2
# andq    %rdx, %r8
and    a4, a4, a2
# andq    %rdx, %r9
and    a5, a5, a2
# andq    %rdx, %r10
and    t0, t0, a2
# andq    %rdx, %r11
and    t1, t1, a2
# andq    %rdx, %r12
and    s2, s2, a2
# andq    %rdx, %r13
and    s3, s3, a2
# addq    %r8, %r14
add    s4, s4, a4
sltu    t2, s4, a4
# adcq    %r9, %r15
add    s5, s5, t2
sltu    t2, s5, t2
add    s5, s5, a5
sltu    a5, s5, a5
or    t2, t2, a5
# movq    %r14, 48(%rdi)
sd    s4, 48(a0)
# adcq    %r10, %rax
add    a6, a6, t2
sltu    t2, a6, t2
add    a6, a6, t0
sltu    t0, a6, t0
or    t2, t2, t0
# movq    %r15, 56(%rdi)
sd    s5, 56(a0)
# adcq    %r11, %rbx
add    s1, s1, t2
sltu    t2, s1, t2
add    s1, s1, t1
sltu    t1, s1, t1
or    t2, t2, t1
# movq    %rax, 64(%rdi)
sd    a6, 64(a0)
# adcq    %r12, %rbp
add    fp, fp, t2
sltu    t2, fp, t2
add    fp, fp, s2
sltu    s2, fp, s2
or    t2, t2, s2
# movq    %rbx, 72(%rdi)
sd    s1, 72(a0)
# adcq    %r13, %rsi
add    a1, a1, t2
sltu    t2, a1, t2
add    a1, a1, s3
sltu    s3, a1, s3
or    t2, t2, s3
# movq    %rbp, 80(%rdi)
sd    fp, 80(a0)
# movq    %rsi, 88(%rdi)
sd    a1, 88(a0)
# .byte    0xf3, 0xc3
ld ra, 0(sp)
addi sp, sp, 8
ret    
# __blst_mulq_by_1_mont_384:    
.globl    __blst_mulq_by_1_mont_384
.align    4
__blst_mulq_by_1_mont_384:
addi sp, sp, -8
sd ra, 0(sp)
# .byte    0xf3, 0x0f, 0x1e, 0xfa
# special directive: ['.byte', '0xf3', '0x0f', '0x1e', '0xfa']
# movq    0(%rsi), %rax
ld    a6, 0(a1)
# movq    8(%rsi), %r9
ld    a5, 8(a1)
# movq    16(%rsi), %r10
ld    t0, 16(a1)
# movq    24(%rsi), %r11
ld    t1, 24(a1)
# movq    32(%rsi), %r12
ld    s2, 32(a1)
# movq    40(%rsi), %r13
ld    s3, 40(a1)
# movq    %rax, %r14
add    s4, a6, zero
# imulq    %rcx, %rax
mul    a6, a6, a3
# movq    %rax, %r8
add    a4, a6, zero
# mulq    0(%rbx)
ld    t6, 0(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    %rdx, %r14
add    s4, s4, t2
sltu    t2, s4, t2
add    s4, s4, a2
sltu    a2, s4, a2
or    t2, t2, a2
# mulq    8(%rbx)
ld    t6, 8(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r14, %r9
add    a5, a5, s4
sltu    t2, a5, s4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r14
add    s4, a2, zero
# mulq    16(%rbx)
ld    t6, 16(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r14, %r10
add    t0, t0, s4
sltu    t2, t0, s4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r14
add    s4, a2, zero
# mulq    24(%rbx)
ld    t6, 24(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %r9, %r15
add    s5, a5, zero
# imulq    %rcx, %r9
mul    a5, a5, a3
# addq    %r14, %r11
add    t1, t1, s4
sltu    t2, t1, s4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r14
add    s4, a2, zero
# mulq    32(%rbx)
ld    t6, 32(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %r8, %rax
add    a6, a4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r14, %r12
add    s2, s2, s4
sltu    t2, s2, s4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r14
add    s4, a2, zero
# mulq    40(%rbx)
ld    t6, 40(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r14, %r13
add    s3, s3, s4
sltu    t2, s3, s4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r14
add    s4, a2, zero
# mulq    0(%rbx)
ld    t6, 0(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    %rdx, %r15
add    s5, s5, t2
sltu    t2, s5, t2
add    s5, s5, a2
sltu    a2, s5, a2
or    t2, t2, a2
# mulq    8(%rbx)
ld    t6, 8(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r15, %r10
add    t0, t0, s5
sltu    t2, t0, s5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r15
add    s5, a2, zero
# mulq    16(%rbx)
ld    t6, 16(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r15, %r11
add    t1, t1, s5
sltu    t2, t1, s5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r15
add    s5, a2, zero
# mulq    24(%rbx)
ld    t6, 24(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %r10, %r8
add    a4, t0, zero
# imulq    %rcx, %r10
mul    t0, t0, a3
# addq    %r15, %r12
add    s2, s2, s5
sltu    t2, s2, s5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r15
add    s5, a2, zero
# mulq    32(%rbx)
ld    t6, 32(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r9, %rax
add    a6, a5, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r15, %r13
add    s3, s3, s5
sltu    t2, s3, s5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r15
add    s5, a2, zero
# mulq    40(%rbx)
ld    t6, 40(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r15, %r14
add    s4, s4, s5
sltu    t2, s4, s5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r15
add    s5, a2, zero
# mulq    0(%rbx)
ld    t6, 0(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    %rdx, %r8
add    a4, a4, t2
sltu    t2, a4, t2
add    a4, a4, a2
sltu    a2, a4, a2
or    t2, t2, a2
# mulq    8(%rbx)
ld    t6, 8(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %r11
add    t1, t1, a4
sltu    t2, t1, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    16(%rbx)
ld    t6, 16(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %r12
add    s2, s2, a4
sltu    t2, s2, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    24(%rbx)
ld    t6, 24(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %r11, %r9
add    a5, t1, zero
# imulq    %rcx, %r11
mul    t1, t1, a3
# addq    %r8, %r13
add    s3, s3, a4
sltu    t2, s3, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    32(%rbx)
ld    t6, 32(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r10, %rax
add    a6, t0, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %r14
add    s4, s4, a4
sltu    t2, s4, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    40(%rbx)
ld    t6, 40(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r8, %r15
add    s5, s5, a4
sltu    t2, s5, a4
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r8
add    a4, a2, zero
# mulq    0(%rbx)
ld    t6, 0(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    %rdx, %r9
add    a5, a5, t2
sltu    t2, a5, t2
add    a5, a5, a2
sltu    a2, a5, a2
or    t2, t2, a2
# mulq    8(%rbx)
ld    t6, 8(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r12
add    s2, s2, a6
sltu    t2, s2, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r12
add    s2, s2, a5
sltu    t2, s2, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    16(%rbx)
ld    t6, 16(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r13
add    s3, s3, a5
sltu    t2, s3, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    24(%rbx)
ld    t6, 24(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %r12, %r10
add    t0, s2, zero
# imulq    %rcx, %r12
mul    s2, s2, a3
# addq    %r9, %r14
add    s4, s4, a5
sltu    t2, s4, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    32(%rbx)
ld    t6, 32(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %r11, %rax
add    a6, t1, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r15
add    s5, s5, a5
sltu    t2, s5, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    40(%rbx)
ld    t6, 40(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r9, %r8
add    a4, a4, a5
sltu    t2, a4, a5
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r9
add    a5, a2, zero
# mulq    0(%rbx)
ld    t6, 0(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    %rdx, %r10
add    t0, t0, t2
sltu    t2, t0, t2
add    t0, t0, a2
sltu    a2, t0, a2
or    t2, t2, a2
# mulq    8(%rbx)
ld    t6, 8(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r13
add    s3, s3, a6
sltu    t2, s3, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r13
add    s3, s3, t0
sltu    t2, s3, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    16(%rbx)
ld    t6, 16(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r14
add    s4, s4, t0
sltu    t2, s4, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    24(%rbx)
ld    t6, 24(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %r13, %r11
add    t1, s3, zero
# imulq    %rcx, %r13
mul    s3, s3, a3
# addq    %r10, %r15
add    s5, s5, t0
sltu    t2, s5, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    32(%rbx)
ld    t6, 32(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %r12, %rax
add    a6, s2, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r8
add    a4, a4, t0
sltu    t2, a4, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    40(%rbx)
ld    t6, 40(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r10, %r9
add    a5, a5, t0
sltu    t2, a5, t0
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r10
add    t0, a2, zero
# mulq    0(%rbx)
ld    t6, 0(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r11
add    t1, t1, a6
sltu    t2, t1, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    %rdx, %r11
add    t1, t1, t2
sltu    t2, t1, t2
add    t1, t1, a2
sltu    a2, t1, a2
or    t2, t2, a2
# mulq    8(%rbx)
ld    t6, 8(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r14
add    s4, s4, a6
sltu    t2, s4, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r14
add    s4, s4, t1
sltu    t2, s4, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    16(%rbx)
ld    t6, 16(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r15
add    s5, s5, a6
sltu    t2, s5, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r15
add    s5, s5, t1
sltu    t2, s5, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    24(%rbx)
ld    t6, 24(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r8
add    a4, a4, a6
sltu    t2, a4, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r8
add    a4, a4, t1
sltu    t2, a4, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    32(%rbx)
ld    t6, 32(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r9
add    a5, a5, a6
sltu    t2, a5, a6
# movq    %r13, %rax
add    a6, s3, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r9
add    a5, a5, t1
sltu    t2, a5, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# mulq    40(%rbx)
ld    t6, 40(s1)
mulhu    a2, t6, a6
mul    a6, t6, a6
# addq    %rax, %r10
add    t0, t0, a6
sltu    t2, t0, a6
# movq    %r14, %rax
add    a6, s4, zero
# adcq    $0, %rdx
add    a2, t2, a2
# addq    %r11, %r10
add    t0, t0, t1
sltu    t2, t0, t1
# adcq    $0, %rdx
add    a2, t2, a2
# movq    %rdx, %r11
add    t1, a2, zero
# .byte    0xf3, 0xc3
ld ra, 0(sp)
addi sp, sp, 8
ret    
# __blst_redc_tail_mont_384:    
.globl    __blst_redc_tail_mont_384
.align    4
__blst_redc_tail_mont_384:
addi sp, sp, -8
sd ra, 0(sp)
# .byte    0xf3, 0x0f, 0x1e, 0xfa
# special directive: ['.byte', '0xf3', '0x0f', '0x1e', '0xfa']
# addq    48(%rsi), %r14
ld    t6, 48(a1)
add    s4, t6, s4
sltu    t2, s4, t6
# movq    %r14, %rax
add    a6, s4, zero
# adcq    56(%rsi), %r15
ld    t6, 56(a1)
add    s5, s5, t2
sltu    t2, s5, t2
add    s5, s5, t6
sltu    t6, s5, t6
or    t2, t2, t6
# adcq    64(%rsi), %r8
ld    t6, 64(a1)
add    a4, a4, t2
sltu    t2, a4, t2
add    a4, a4, t6
sltu    t6, a4, t6
or    t2, t2, t6
# adcq    72(%rsi), %r9
ld    t6, 72(a1)
add    a5, a5, t2
sltu    t2, a5, t2
add    a5, a5, t6
sltu    t6, a5, t6
or    t2, t2, t6
# movq    %r15, %rcx
add    a3, s5, zero
# adcq    80(%rsi), %r10
ld    t6, 80(a1)
add    t0, t0, t2
sltu    t2, t0, t2
add    t0, t0, t6
sltu    t6, t0, t6
or    t2, t2, t6
# adcq    88(%rsi), %r11
ld    t6, 88(a1)
add    t1, t1, t2
sltu    t2, t1, t2
add    t1, t1, t6
sltu    t6, t1, t6
or    t2, t2, t6
# sbbq    %r12, %r12
sub    s2, zero, t2
# movq    %r8, %rdx
add    a2, a4, zero
# movq    %r9, %rbp
add    fp, a5, zero
# subq    0(%rbx), %r14
ld    t6, 0(s1)
sltu    t2, s4, t6
sub    s4, s4, t6
# sbbq    8(%rbx), %r15
ld    t6, 8(s1)
sub    t2, s5, t2
sltu    a7, s5, t2
sub    s5, t2, t6
sltu    t6, t2, s5
or    t2, t6, a7
# movq    %r10, %r13
add    s3, t0, zero
# sbbq    16(%rbx), %r8
ld    t6, 16(s1)
sub    t2, a4, t2
sltu    a7, a4, t2
sub    a4, t2, t6
sltu    t6, t2, a4
or    t2, t6, a7
# sbbq    24(%rbx), %r9
ld    t6, 24(s1)
sub    t2, a5, t2
sltu    a7, a5, t2
sub    a5, t2, t6
sltu    t6, t2, a5
or    t2, t6, a7
# sbbq    32(%rbx), %r10
ld    t6, 32(s1)
sub    t2, t0, t2
sltu    a7, t0, t2
sub    t0, t2, t6
sltu    t6, t2, t0
or    t2, t6, a7
# movq    %r11, %rsi
add    a1, t1, zero
# sbbq    40(%rbx), %r11
ld    t6, 40(s1)
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
beq    t2, zero, .LABLE7
add    s4, a6, zero
.LABLE7:
# cmovcq    %rcx, %r15
beq    t2, zero, .LABLE8
add    s5, a3, zero
.LABLE8:
# cmovcq    %rdx, %r8
beq    t2, zero, .LABLE9
add    a4, a2, zero
.LABLE9:
# movq    %r14, 0(%rdi)
sd    s4, 0(a0)
# cmovcq    %rbp, %r9
beq    t2, zero, .LABLE10
add    a5, fp, zero
.LABLE10:
# movq    %r15, 8(%rdi)
sd    s5, 8(a0)
# cmovcq    %r13, %r10
beq    t2, zero, .LABLE11
add    t0, s3, zero
.LABLE11:
# movq    %r8, 16(%rdi)
sd    a4, 16(a0)
# cmovcq    %rsi, %r11
beq    t2, zero, .LABLE12
add    t1, a1, zero
.LABLE12:
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
