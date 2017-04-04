#!/usr/bin/perl -w
#
# Double SHA-256 implemented for Bitcoin in AMD CAL IL.
#
# Author: Marc Bevand <m.bevand (at) gmail.com>

use strict;

my $code;
my $elm_per_threads = 4; # keep in sync with ELM_PER_THREAD in C code
my ($zero, $zero_e, $one, $one_e, $s_found, $s_finished,
    $tmp0, $tmp1, $tmp2, $tmp3);
my ($v2, $v6, $v7, $v17);
my ($v13, $v11, $v18, $v19);
my ($v22, $v25, $v3, $v10);

# Returns the constant k[i] used in the given step (cb0[?].?).
#
# $i 0..63 step number
sub step_to_k_i
{
    my ($step) = @_;
    my @elm = qw/xxxx yyyy zzzz wwww/;
    die "*bug*: step cannot be $step\n" if $step >= 64;
    return sprintf "cb0[%i].%s", $step / 4, $elm[$step % 4];
}

# Returns the register containing the given data word
#
# $i 0..63
sub w
{
    my ($i) = @_;
    die "*bug*: invalid data word: $i" if ($i < 0 or $i > 63);
    # the 64 words are accessed through a 16-register window
    $i = $i % 16;
    # first word is in r9
    return sprintf 'r%d', (9 + $i);
}

# Returns the register holding the given intermediate hash value.
#
# $ihv a..h
sub ihv_reg
{
    my ($ihv) = @_;
    my $v = ord($ihv) - ord('a');
    die "*bug*: invalid v value: $v" if ($v < 0 or $v > 7);
    # A is stored in r1
    return sprintf "r%d", (1 + $v);
}

# tmp2 = ror32(x, 7) ^ ror32(x,18) ^ (x >> 3)
sub sigma0
{
    my ($x) = @_;
    $code .=
    "    bitalign $tmp0, $x, $x, $v7\n".
    "    bitalign $tmp1, $x, $x, $v18\n".
    "    ixor $tmp0, $tmp0, $tmp1\n".
    "    ushr $tmp1, $x, $v3\n".
    "    ixor $tmp2, $tmp0, $tmp1\n";
}

# tmp1 = ror32(x,17) ^ ror32(x,19) ^ (x >> 10)
sub sigma1
{
    my ($x) = @_;
    $code .=
    "    bitalign $tmp1, $x, $x, $v17\n".
    "    bitalign $tmp0, $x, $x, $v19\n".
    "    ixor $tmp1, $tmp1, $tmp0\n".
    "    ushr $tmp0, $x, $v10\n".
    "    ixor $tmp1, $tmp1, $tmp0\n";
}

# compute a word by blending previous ones: w[i] = s0 + s1 + w[i-16] + w[i-7]
#
# $i 16..63 word to blend
sub sha256_blend
{
    my ($i) = @_;
    die "*bug*: i is too small" if $i < 16;
    $code .= "\n    ; blend word $i\n";
    sigma0(w($i - 15));
    sigma1(w($i - 2));
    $code .=
    "    iadd $tmp0, $tmp2, $tmp1\n".
    "    iadd $tmp0, $tmp0, ".w($i - 16)."\n".
    "    iadd ".w($i).", $tmp0, ".w($i - 7)."\n";
}

# tmp2 = ror32(x, 2) ^ ror32(x,13) ^ ror32(x,22)
sub bigsigma0
{
    my ($x) = @_;
    $code .=
    "    bitalign $tmp0, $x, $x, $v2\n".
    "    bitalign $tmp1, $x, $x, $v13\n".
    "    ixor $tmp0, $tmp0, $tmp1\n".
    "    bitalign $tmp1, $x, $x, $v22\n".
    "    ixor $tmp2, $tmp0, $tmp1\n";
}

# tmp0 = (a and b) xor (a and c) xor (b and c)
# Faster equivalent (only 4 ops):
# tmp0 = (a and b) or (c and (a or b))
# Can be implemented in 2 ops with BFI_INT:
# tmp0 = (a ^ b) ? c : a
sub maj
{
    my ($step, $a, $b, $c) = @_;
    # A B C are known before step 0, allowing the IL compiler to pre-compile
    # results of these instructions. If ibit_extract was used it would lead
    # to incorrect results, so only use it during steps 1..63.
    if ($step == 0) {
        $code .=
        "    iand $tmp0, $a, $b\n".
        "    ior $tmp1, $a, $b\n".
        "    iand $tmp1, $tmp1, $c\n".
        "    ior $tmp0, $tmp0, $tmp1\n";
    } else {
        # ibit_extract patched to BFI_INT at runtime
        $code .=
        "    ixor $tmp0, $a, $b\n".
        "    ibit_extract $tmp0, $a, $c, $tmp0\n";
    }
}

# tmp3 = ror32(x, 6) ^ ror32(x,11) ^ ror32(x,25)
sub bigsigma1
{
    my ($x) = @_;
    $code .=
    "    bitalign $tmp0, $x, $x, $v6\n".
    "    bitalign $tmp1, $x, $x, $v11\n".
    "    ixor $tmp0, $tmp0, $tmp1\n".
    "    bitalign $tmp1, $x, $x, $v25\n".
    "    ixor $tmp3, $tmp0, $tmp1\n";
}

# tmp1 = (e and f) xor ((not e) and g)
# Can be implemented in 1 op with BFI_INT (e is the mask):
# tmp1 = e ? (f) : (g)
sub ch
{
    my ($step, $e, $f, $g) = @_;
    # E F G are known before step 0, allowing the IL compiler to optimize
    # out these instructions. If ibit_extract was used it would lead to
    # incorrect results, so only use it during steps 1..63.
    if ($step == 0) {
	$code .=
	"    iand $tmp0, $e, $f\n".
	"    inot $tmp1, $e\n".
	"    iand $tmp1, $tmp1, $g\n".
	"    ior $tmp1, $tmp0, $tmp1\n";
    } else {
        # ibit_extract patched to BFI_INT at runtime
	$code .=
	"    ibit_extract $tmp1, $g, $f, $e\n";
    }
}

# implement a SHA-256 round
sub sha256_round
{
    my ($step) = @_;
    my $a = ihv_reg($_[1]);
    my $b = ihv_reg($_[2]);
    my $c = ihv_reg($_[3]);
    my $d = ihv_reg($_[4]);
    my $e = ihv_reg($_[5]);
    my $f = ihv_reg($_[6]);
    my $g = ihv_reg($_[7]);
    my $h = ihv_reg($_[8]);
    my $k_i = step_to_k_i($step);
    sha256_blend($step) if $step >= 16;
    $code .= "\n    ; step $step\n";
    bigsigma0($a);
    maj($step, $a, $b, $c);
    $code .= "    iadd $tmp2, $tmp2, $tmp0\n"; # this is t2
    bigsigma1($e);
    ch($step, $e, $f, $g);
    $code .=
    "    iadd $tmp0, $tmp3, $tmp1\n".
    "    iadd $tmp0, $tmp0, $h\n".
    "    iadd $tmp0, $tmp0, $k_i\n".
    "    iadd $tmp1, $tmp0, ".w($step)."\n"; # this is t1
    # d = d + t1
    $code .= "    iadd $d, $d, $tmp1\n";
    # h = t1 + t2
    $code .= "    iadd $h, $tmp1, $tmp2\n";
}

sub execute_64rounds
{
    my ($num) = @_;

    my $s = 0;
    sha256_round($s++, qw/a b c d e f g h/);
    sha256_round($s++, qw/h a b c d e f g/);
    sha256_round($s++, qw/g h a b c d e f/);
    sha256_round($s++, qw/f g h a b c d e/);
    sha256_round($s++, qw/e f g h a b c d/);
    sha256_round($s++, qw/d e f g h a b c/);
    sha256_round($s++, qw/c d e f g h a b/);
    sha256_round($s++, qw/b c d e f g h a/);
    sha256_round($s++, qw/a b c d e f g h/);
    sha256_round($s++, qw/h a b c d e f g/);
    sha256_round($s++, qw/g h a b c d e f/);
    sha256_round($s++, qw/f g h a b c d e/);
    sha256_round($s++, qw/e f g h a b c d/);
    sha256_round($s++, qw/d e f g h a b c/);
    sha256_round($s++, qw/c d e f g h a b/);
    sha256_round($s++, qw/b c d e f g h a/);
    sha256_round($s++, qw/a b c d e f g h/);
    sha256_round($s++, qw/h a b c d e f g/);
    sha256_round($s++, qw/g h a b c d e f/);
    sha256_round($s++, qw/f g h a b c d e/);
    sha256_round($s++, qw/e f g h a b c d/);
    sha256_round($s++, qw/d e f g h a b c/);
    sha256_round($s++, qw/c d e f g h a b/);
    sha256_round($s++, qw/b c d e f g h a/);
    sha256_round($s++, qw/a b c d e f g h/);
    sha256_round($s++, qw/h a b c d e f g/);
    sha256_round($s++, qw/g h a b c d e f/);
    sha256_round($s++, qw/f g h a b c d e/);
    sha256_round($s++, qw/e f g h a b c d/);
    sha256_round($s++, qw/d e f g h a b c/);
    sha256_round($s++, qw/c d e f g h a b/);
    sha256_round($s++, qw/b c d e f g h a/);
    sha256_round($s++, qw/a b c d e f g h/);
    sha256_round($s++, qw/h a b c d e f g/);
    sha256_round($s++, qw/g h a b c d e f/);
    sha256_round($s++, qw/f g h a b c d e/);
    sha256_round($s++, qw/e f g h a b c d/);
    sha256_round($s++, qw/d e f g h a b c/);
    sha256_round($s++, qw/c d e f g h a b/);
    sha256_round($s++, qw/b c d e f g h a/);
    sha256_round($s++, qw/a b c d e f g h/);
    sha256_round($s++, qw/h a b c d e f g/);
    sha256_round($s++, qw/g h a b c d e f/);
    sha256_round($s++, qw/f g h a b c d e/);
    sha256_round($s++, qw/e f g h a b c d/);
    sha256_round($s++, qw/d e f g h a b c/);
    sha256_round($s++, qw/c d e f g h a b/);
    sha256_round($s++, qw/b c d e f g h a/);
    sha256_round($s++, qw/a b c d e f g h/);
    sha256_round($s++, qw/h a b c d e f g/);
    sha256_round($s++, qw/g h a b c d e f/);
    sha256_round($s++, qw/f g h a b c d e/);
    sha256_round($s++, qw/e f g h a b c d/);
    sha256_round($s++, qw/d e f g h a b c/);
    sha256_round($s++, qw/c d e f g h a b/);
    sha256_round($s++, qw/b c d e f g h a/);
    sha256_round($s++, qw/a b c d e f g h/);
    sha256_round($s++, qw/h a b c d e f g/);
    sha256_round($s++, qw/g h a b c d e f/);
    sha256_round($s++, qw/f g h a b c d e/);
    sha256_round($s++, qw/e f g h a b c d/);
    if ($num == 0) {
        # this optimization (only executing the last 3 rounds of the first hash)
        # is technically not necessary to be made explicitely because the CAL
        # compiler is able to get rid of this unnecessary code by itself
        sha256_round($s++, qw/d e f g h a b c/);
        sha256_round($s++, qw/c d e f g h a b/);
        sha256_round($s++, qw/b c d e f g h a/);
    }
}

sub generate_kernel
{
    my ($fname) = @_;
    $zero_e = 'l0.z';
    $zero = $zero_e.'zzz';
    $one_e = 'l0.w';
    $one = $one_e.'www';
    $s_found = 'l1.x';
    $s_finished = 'l1.y';
    ($v2, $v6, $v7, $v17) =    qw/l5.xxxx l5.yyyy l5.zzzz l5.wwww/;
    ($v13, $v11, $v18, $v19) = qw/l6.xxxx l6.yyyy l6.zzzz l6.wwww/;
    ($v22, $v25, $v3, $v10) =  qw/l7.xxxx l7.yyyy l7.zzzz l7.wwww/;
    $code = "";
    $code .= <<EOF;
il_cs
  dcl_num_thread_per_group %d
  ;  SHA256 round constants
  dcl_cb cb0[16]
  ;  l0.x number of iterations
  ;  l0.y used to access g[], must be sizeof (thread_state_t) / 16
  ;  $zero_e 0, used in various places
  ;  $one_e 1, used in various places
  dcl_literal l0, %u, %lu, 0, 1
  ;  $s_found value of s_found
  ;  $s_finished value of s_finished
  ;  l1.z msg length in bits for second hash (ie. word 15)
  ;  l1.w data word 0
  dcl_literal l1, %d, %d, 0x100, %u
  ;  l2.x data word 1
  ;  l2.y data word 2
  ;  l2.z data word 4 (end-of-msg bit, re-used for second hash too)
  ;  l2.w data msg length in bits for first hash (ie. word 15)
  dcl_literal l2, %u, %u, 0x80000000, 0x280
  ;  l3-l4 SHA256 intermediate hash values (for first hash)
  dcl_literal l3, %u, %u, %u, %u
  dcl_literal l4, %u, %u, %u, %u
  ;  l5-l7 rotate and shift values
  dcl_literal l5, 2, 6, 7, 17
  dcl_literal l6, 13, 11, 18, 19
  dcl_literal l7, 22, 25, 3, 10
  ;  l8-l9 SHA256 initial hash values (for second hash)
  dcl_literal l8, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
  dcl_literal l9, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

  ; r0.x    offset to this thread's state in g[]
  ; r0.y    iteration counter
  ; r1-r8   A,B,C,D,E,F,G,H
  ; r9-r24  16 data words, re-used to process all 64 data words
  ; r73     current nonce
  ; r74     end nonce
EOF
    $tmp0 = 'r75';
    $tmp1 = 'r76';
    $tmp2 = 'r77';
    $tmp3 = 'r78';
    $code .= <<EOF;
  ; $tmp0   temp value
  ; $tmp1   temp value
  ; $tmp2   temp value
  ; $tmp3   temp value

  umul r0.x, vAbsTidFlat.x, l0.y

  ; load current nonce
  mov r73.x, g[r0.x+0].y
  mov r73.y, g[r0.x+1].y
  mov r73.z, g[r0.x+2].y
  mov r73.w, g[r0.x+3].y
  ; load end nonce
  mov r74.x, g[r0.x+0].z
  mov r74.y, g[r0.x+1].z
  mov r74.z, g[r0.x+2].z
  mov r74.w, g[r0.x+3].z

  ixor r0.y, r0.y, r0.y

  whileloop
    ; load data words 0-4
    mov r9, l1.wwww
    mov r10, l2.xxxx
    mov r11, l2.yyyy
    mov r12, r73     ; current nonce
    mov r13, l2.zzzz
    ; load data words 5-14 (all zero)
    mov r14, $zero
    mov r15, $zero
    mov r16, $zero
    mov r17, $zero
    mov r18, $zero
    mov r19, $zero
    mov r20, $zero
    mov r21, $zero
    mov r22, $zero
    mov r23, $zero
    ; load data word 15 (bit length)
    mov r24, l2.wwww

    ; init intermediate hash values
    mov r1, l3.xxxx
    mov r2, l3.yyyy
    mov r3, l3.zzzz
    mov r4, l3.wwww
    mov r5, l4.xxxx
    mov r6, l4.yyyy
    mov r7, l4.zzzz
    mov r8, l4.wwww

EOF

    execute_64rounds(0);

    $code .= <<EOF;

    ; add A,B,C,D,E,F,G,H to intermediate hash values, and store them in
    ; data words for next SHA-256 hash computation
    iadd r9, r1, l3.xxxx
    iadd r10, r2, l3.yyyy
    iadd r11, r3, l3.zzzz
    iadd r12, r4, l3.wwww
    iadd r13, r5, l4.xxxx
    iadd r14, r6, l4.yyyy
    iadd r15, r7, l4.zzzz
    iadd r16, r8, l4.wwww
    ; init rest of the data words
    mov r17, l2.zzzz ; end-of-message bit
    ; r18-r23 reset to zero
    mov r18, $zero
    mov r19, $zero
    mov r20, $zero
    mov r21, $zero
    mov r22, $zero
    mov r23, $zero
    mov r24, l1.zzzz

    ; init intermediate hash values
    mov r1, l8.xxxx
    mov r2, l8.yyyy
    mov r3, l8.zzzz
    mov r4, l8.wwww
    mov r5, l9.xxxx
    mov r6, l9.yyyy
    mov r7, l9.zzzz
    mov r8, l9.wwww

EOF

    execute_64rounds(1);

    $code .= <<EOF;

    ; add A,B,C,D,E,F,G,H to intermediate hash values
    iadd r1, r1, l8.xxxx
    iadd r2, r2, l8.yyyy
    iadd r3, r3, l8.zzzz
    iadd r4, r4, l8.wwww
    iadd r5, r5, l9.xxxx
    iadd r6, r6, l9.yyyy
    iadd r7, r7, l9.zzzz
    iadd r8, r8, l9.wwww

    ; increment iteration counter and nonce
    iadd r0.y, r0.y, $one_e
    iadd r73, r73, $one

    ; set bits in $tmp0 if H is zero
    ieq $tmp0, r8, $zero

    ; set bits in $tmp0 if we have iterated too many times
    ieq $tmp1.x, r0.y, l0.x
    ior $tmp0.x, $tmp0.x, $tmp1.x

    ; set bits in $tmp0 if we have reach the end nonce
    ieq $tmp1, r73, r74
    ior $tmp0, $tmp0, $tmp1

    ; if $tmp0 has any bit set, break
    ior $tmp0.xy, $tmp0.xy, $tmp0.zw
    ior $tmp0.x, $tmp0.x, $tmp0.y
    break_logicalnz $tmp0.x
  endloop

EOF
    $code .= " mov g[r0.x+0].w, r8.x ; DEBUG\n";

    my $i = 0;
    foreach my $c (qw/x y z w/) {
	my $status = sprintf 'g[r0.x+%d].x', $i;
	my $cur_nonce = sprintf 'g[r0.x+%d].y', $i;
	$code .= <<EOF;
  ; looking at component $c
  mov $status, $zero_e ; s_searching
  if_logicalz r8.$c
    mov $status, $s_found
  else
    ieq $tmp0.x, r73.$c, r74.$c
    if_logicalnz $tmp0.x
      mov $status, $s_finished
    endif
  endif
  mov $cur_nonce, r73.$c
EOF
	$i++;
    }
    $code .= <<EOF;
endmain

;_the_end_
end
EOF

# $code contains a compute shader program:
#   il_cs
#     ...
#   end
# now it is transformed to a C macro string:
#   #define KERNEL \
#   "il_cs\
#     ...\
#   end\
#   "
    chomp $code;
    $code =~ s/"/\\"/g;
    $code =~ s/$/\\n\\/gm;
    my $macro_name = $fname;
    $macro_name =~ s/\.h$//;
    $macro_name =~ s/-/_/g;
    $macro_name = uc($macro_name);
    $code = "#define $macro_name \\\n\"$code\n\"\n";
    my $fh;
    open($fh, ">", $fname) or die "can't open $fname: $!";
    print { $fh } $code;
    close($fh) or die "can't close $fname: $!";
}

generate_kernel("kernel-sha256.h");
# eof
