/*
 * calc_addrs_ed25519.cl - OpenCL kernel for Ed25519 vanity address generation
 *
 * Ported from solanity (CUDA) to OpenCL.
 * Original Ed25519 implementation derived from SUPERCOP ref10 (public domain).
 *
 * Usage: each work item receives a 32-byte seed (from /dev/urandom on host),
 * generates keys_per_item Ed25519 keypairs by SHA512+clamp+scalar_mult,
 * and writes the 32-byte public keys to the output buffer.
 * Pattern matching is done on the CPU side.
 */

/* ============================================================
 * Section A: Common utilities (ported from common.cu)
 * ============================================================ */

static ulong load_3(const uchar *in) {
    ulong result;
    result  = (ulong) in[0];
    result |= ((ulong) in[1]) << 8;
    result |= ((ulong) in[2]) << 16;
    return result;
}

static ulong load_4(const uchar *in) {
    ulong result;
    result  = (ulong) in[0];
    result |= ((ulong) in[1]) << 8;
    result |= ((ulong) in[2]) << 16;
    result |= ((ulong) in[3]) << 24;
    return result;
}

/* ============================================================
 * Section B: GF(2^255-19) Field Arithmetic (ported from fe.cu)
 *
 * fe = int[10], radix 2^25.5 representation.
 * Each limb t[i] represents value in:
 *   t[0] + 2^26*t[1] + 2^51*t[2] + 2^77*t[3] + 2^102*t[4] + ...
 * ============================================================ */

typedef int fe[10];

static void fe_0(fe h) {
    h[0]=0; h[1]=0; h[2]=0; h[3]=0; h[4]=0;
    h[5]=0; h[6]=0; h[7]=0; h[8]=0; h[9]=0;
}

static void fe_1(fe h) {
    h[0]=1; h[1]=0; h[2]=0; h[3]=0; h[4]=0;
    h[5]=0; h[6]=0; h[7]=0; h[8]=0; h[9]=0;
}

static void fe_add(fe h, const fe f, const fe g) {
    h[0]=f[0]+g[0]; h[1]=f[1]+g[1]; h[2]=f[2]+g[2]; h[3]=f[3]+g[3]; h[4]=f[4]+g[4];
    h[5]=f[5]+g[5]; h[6]=f[6]+g[6]; h[7]=f[7]+g[7]; h[8]=f[8]+g[8]; h[9]=f[9]+g[9];
}

static void fe_sub(fe h, const fe f, const fe g) {
    h[0]=f[0]-g[0]; h[1]=f[1]-g[1]; h[2]=f[2]-g[2]; h[3]=f[3]-g[3]; h[4]=f[4]-g[4];
    h[5]=f[5]-g[5]; h[6]=f[6]-g[6]; h[7]=f[7]-g[7]; h[8]=f[8]-g[8]; h[9]=f[9]-g[9];
}

static void fe_neg(fe h, const fe f) {
    h[0]=-f[0]; h[1]=-f[1]; h[2]=-f[2]; h[3]=-f[3]; h[4]=-f[4];
    h[5]=-f[5]; h[6]=-f[6]; h[7]=-f[7]; h[8]=-f[8]; h[9]=-f[9];
}

static void fe_copy(fe h, const fe f) {
    h[0]=f[0]; h[1]=f[1]; h[2]=f[2]; h[3]=f[3]; h[4]=f[4];
    h[5]=f[5]; h[6]=f[6]; h[7]=f[7]; h[8]=f[8]; h[9]=f[9];
}

static void fe_cmov(fe f, const fe g, uint b) {
    int f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4],f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
    int g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4],g5=g[5],g6=g[6],g7=g[7],g8=g[8],g9=g[9];
    int x0=f0^g0,x1=f1^g1,x2=f2^g2,x3=f3^g3,x4=f4^g4;
    int x5=f5^g5,x6=f6^g6,x7=f7^g7,x8=f8^g8,x9=f9^g9;
    b = (uint)(-(int)b);
    x0&=b; x1&=b; x2&=b; x3&=b; x4&=b; x5&=b; x6&=b; x7&=b; x8&=b; x9&=b;
    f[0]=f0^x0; f[1]=f1^x1; f[2]=f2^x2; f[3]=f3^x3; f[4]=f4^x4;
    f[5]=f5^x5; f[6]=f6^x6; f[7]=f7^x7; f[8]=f8^x8; f[9]=f9^x9;
}

static void fe_frombytes(fe h, const uchar *s) {
    long h0 = (long)load_4(s);
    long h1 = (long)load_3(s+4) << 6;
    long h2 = (long)load_3(s+7) << 5;
    long h3 = (long)load_3(s+10) << 3;
    long h4 = (long)load_3(s+13) << 2;
    long h5 = (long)load_4(s+16);
    long h6 = (long)load_3(s+20) << 7;
    long h7 = (long)load_3(s+23) << 5;
    long h8 = (long)load_3(s+26) << 4;
    long h9 = (long)(load_3(s+29) & 8388607) << 2;
    long carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;
    carry9=(h9+(long)(1<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry1=(h1+(long)(1<<24))>>25; h2+=carry1; h1-=carry1<<25;
    carry3=(h3+(long)(1<<24))>>25; h4+=carry3; h3-=carry3<<25;
    carry5=(h5+(long)(1<<24))>>25; h6+=carry5; h5-=carry5<<25;
    carry7=(h7+(long)(1<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry0=(h0+(long)(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    carry2=(h2+(long)(1<<25))>>26; h3+=carry2; h2-=carry2<<26;
    carry4=(h4+(long)(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry6=(h6+(long)(1<<25))>>26; h7+=carry6; h6-=carry6<<26;
    carry8=(h8+(long)(1<<25))>>26; h9+=carry8; h8-=carry8<<26;
    h[0]=(int)h0; h[1]=(int)h1; h[2]=(int)h2; h[3]=(int)h3; h[4]=(int)h4;
    h[5]=(int)h5; h[6]=(int)h6; h[7]=(int)h7; h[8]=(int)h8; h[9]=(int)h9;
}

static void fe_tobytes(uchar *s, const fe h) {
    int h0=h[0],h1=h[1],h2=h[2],h3=h[3],h4=h[4],h5=h[5],h6=h[6],h7=h[7],h8=h[8],h9=h[9];
    int q,carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;
    q=(19*h9+(((int)1)<<24))>>25;
    q=(h0+q)>>26; q=(h1+q)>>25; q=(h2+q)>>26; q=(h3+q)>>25;
    q=(h4+q)>>26; q=(h5+q)>>25; q=(h6+q)>>26; q=(h7+q)>>25;
    q=(h8+q)>>26; q=(h9+q)>>25;
    h0+=19*q;
    carry0=h0>>26; h1+=carry0; h0-=carry0<<26;
    carry1=h1>>25; h2+=carry1; h1-=carry1<<25;
    carry2=h2>>26; h3+=carry2; h2-=carry2<<26;
    carry3=h3>>25; h4+=carry3; h3-=carry3<<25;
    carry4=h4>>26; h5+=carry4; h4-=carry4<<26;
    carry5=h5>>25; h6+=carry5; h5-=carry5<<25;
    carry6=h6>>26; h7+=carry6; h6-=carry6<<26;
    carry7=h7>>25; h8+=carry7; h7-=carry7<<25;
    carry8=h8>>26; h9+=carry8; h8-=carry8<<26;
    carry9=h9>>25; h9-=carry9<<25;
    s[0]=(uchar)(h0>>0);  s[1]=(uchar)(h0>>8);  s[2]=(uchar)(h0>>16);
    s[3]=(uchar)((h0>>24)|(h1<<2));
    s[4]=(uchar)(h1>>6);  s[5]=(uchar)(h1>>14);
    s[6]=(uchar)((h1>>22)|(h2<<3));
    s[7]=(uchar)(h2>>5);  s[8]=(uchar)(h2>>13);
    s[9]=(uchar)((h2>>21)|(h3<<5));
    s[10]=(uchar)(h3>>3); s[11]=(uchar)(h3>>11);
    s[12]=(uchar)((h3>>19)|(h4<<6));
    s[13]=(uchar)(h4>>2); s[14]=(uchar)(h4>>10); s[15]=(uchar)(h4>>18);
    s[16]=(uchar)(h5>>0); s[17]=(uchar)(h5>>8);  s[18]=(uchar)(h5>>16);
    s[19]=(uchar)((h5>>24)|(h6<<1));
    s[20]=(uchar)(h6>>7); s[21]=(uchar)(h6>>15);
    s[22]=(uchar)((h6>>23)|(h7<<3));
    s[23]=(uchar)(h7>>5); s[24]=(uchar)(h7>>13);
    s[25]=(uchar)((h7>>21)|(h8<<4));
    s[26]=(uchar)(h8>>4); s[27]=(uchar)(h8>>12);
    s[28]=(uchar)((h8>>20)|(h9<<6));
    s[29]=(uchar)(h9>>2); s[30]=(uchar)(h9>>10); s[31]=(uchar)(h9>>18);
}

static int fe_isnegative(const fe f) {
    uchar s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static int fe_isnonzero(const fe f) {
    uchar s[32];
    fe_tobytes(s, f);
    uchar r = s[0];
    for (int i=1; i<32; i++) r |= s[i];
    return r != 0;
}

static void fe_mul(fe h, const fe f, const fe g) {
    int f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4],f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
    int g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4],g5=g[5],g6=g[6],g7=g[7],g8=g[8],g9=g[9];
    int g1_19=19*g1,g2_19=19*g2,g3_19=19*g3,g4_19=19*g4,g5_19=19*g5;
    int g6_19=19*g6,g7_19=19*g7,g8_19=19*g8,g9_19=19*g9;
    int f1_2=2*f1,f3_2=2*f3,f5_2=2*f5,f7_2=2*f7,f9_2=2*f9;
    long f0g0=f0*(long)g0, f0g1=f0*(long)g1, f0g2=f0*(long)g2, f0g3=f0*(long)g3;
    long f0g4=f0*(long)g4, f0g5=f0*(long)g5, f0g6=f0*(long)g6, f0g7=f0*(long)g7;
    long f0g8=f0*(long)g8, f0g9=f0*(long)g9;
    long f1g0=f1*(long)g0, f1g1_2=f1_2*(long)g1, f1g2=f1*(long)g2, f1g3_2=f1_2*(long)g3;
    long f1g4=f1*(long)g4, f1g5_2=f1_2*(long)g5, f1g6=f1*(long)g6, f1g7_2=f1_2*(long)g7;
    long f1g8=f1*(long)g8, f1g9_38=f1_2*(long)g9_19;
    long f2g0=f2*(long)g0, f2g1=f2*(long)g1, f2g2=f2*(long)g2, f2g3=f2*(long)g3;
    long f2g4=f2*(long)g4, f2g5=f2*(long)g5, f2g6=f2*(long)g6, f2g7=f2*(long)g7;
    long f2g8_19=f2*(long)g8_19, f2g9_19=f2*(long)g9_19;
    long f3g0=f3*(long)g0, f3g1_2=f3_2*(long)g1, f3g2=f3*(long)g2, f3g3_2=f3_2*(long)g3;
    long f3g4=f3*(long)g4, f3g5_2=f3_2*(long)g5, f3g6=f3*(long)g6;
    long f3g7_38=f3_2*(long)g7_19, f3g8_19=f3*(long)g8_19, f3g9_38=f3_2*(long)g9_19;
    long f4g0=f4*(long)g0, f4g1=f4*(long)g1, f4g2=f4*(long)g2, f4g3=f4*(long)g3;
    long f4g4=f4*(long)g4, f4g5=f4*(long)g5;
    long f4g6_19=f4*(long)g6_19, f4g7_19=f4*(long)g7_19;
    long f4g8_19=f4*(long)g8_19, f4g9_19=f4*(long)g9_19;
    long f5g0=f5*(long)g0, f5g1_2=f5_2*(long)g1, f5g2=f5*(long)g2, f5g3_2=f5_2*(long)g3;
    long f5g4=f5*(long)g4;
    long f5g5_38=f5_2*(long)g5_19, f5g6_19=f5*(long)g6_19;
    long f5g7_38=f5_2*(long)g7_19, f5g8_19=f5*(long)g8_19, f5g9_38=f5_2*(long)g9_19;
    long f6g0=f6*(long)g0, f6g1=f6*(long)g1, f6g2=f6*(long)g2, f6g3=f6*(long)g3;
    long f6g4_19=f6*(long)g4_19, f6g5_19=f6*(long)g5_19;
    long f6g6_19=f6*(long)g6_19, f6g7_19=f6*(long)g7_19;
    long f6g8_19=f6*(long)g8_19, f6g9_19=f6*(long)g9_19;
    long f7g0=f7*(long)g0, f7g1_2=f7_2*(long)g1, f7g2=f7*(long)g2;
    long f7g3_38=f7_2*(long)g3_19, f7g4_19=f7*(long)g4_19;
    long f7g5_38=f7_2*(long)g5_19, f7g6_19=f7*(long)g6_19;
    long f7g7_38=f7_2*(long)g7_19, f7g8_19=f7*(long)g8_19, f7g9_38=f7_2*(long)g9_19;
    long f8g0=f8*(long)g0, f8g1=f8*(long)g1;
    long f8g2_19=f8*(long)g2_19, f8g3_19=f8*(long)g3_19;
    long f8g4_19=f8*(long)g4_19, f8g5_19=f8*(long)g5_19;
    long f8g6_19=f8*(long)g6_19, f8g7_19=f8*(long)g7_19;
    long f8g8_19=f8*(long)g8_19, f8g9_19=f8*(long)g9_19;
    long f9g0=f9*(long)g0;
    long f9g1_38=f9_2*(long)g1_19, f9g2_19=f9*(long)g2_19;
    long f9g3_38=f9_2*(long)g3_19, f9g4_19=f9*(long)g4_19;
    long f9g5_38=f9_2*(long)g5_19, f9g6_19=f9*(long)g6_19;
    long f9g7_38=f9_2*(long)g7_19, f9g8_19=f9*(long)g8_19, f9g9_38=f9_2*(long)g9_19;
    long h0=f0g0+f1g9_38+f2g8_19+f3g7_38+f4g6_19+f5g5_38+f6g4_19+f7g3_38+f8g2_19+f9g1_38;
    long h1=f0g1+f1g0+f2g9_19+f3g8_19+f4g7_19+f5g6_19+f6g5_19+f7g4_19+f8g3_19+f9g2_19;
    long h2=f0g2+f1g1_2+f2g0+f3g9_38+f4g8_19+f5g7_38+f6g6_19+f7g5_38+f8g4_19+f9g3_38;
    long h3=f0g3+f1g2+f2g1+f3g0+f4g9_19+f5g8_19+f6g7_19+f7g6_19+f8g5_19+f9g4_19;
    long h4=f0g4+f1g3_2+f2g2+f3g1_2+f4g0+f5g9_38+f6g8_19+f7g7_38+f8g6_19+f9g5_38;
    long h5=f0g5+f1g4+f2g3+f3g2+f4g1+f5g0+f6g9_19+f7g8_19+f8g7_19+f9g6_19;
    long h6=f0g6+f1g5_2+f2g4+f3g3_2+f4g2+f5g1_2+f6g0+f7g9_38+f8g8_19+f9g7_38;
    long h7=f0g7+f1g6+f2g5+f3g4+f4g3+f5g2+f6g1+f7g0+f8g9_19+f9g8_19;
    long h8=f0g8+f1g7_2+f2g6+f3g5_2+f4g4+f5g3_2+f6g2+f7g1_2+f8g0+f9g9_38;
    long h9=f0g9+f1g8+f2g7+f3g6+f4g5+f5g4+f6g3+f7g2+f8g1+f9g0;
    long carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;
    carry0=(h0+(long)(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    carry4=(h4+(long)(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry1=(h1+(long)(1<<24))>>25; h2+=carry1; h1-=carry1<<25;
    carry5=(h5+(long)(1<<24))>>25; h6+=carry5; h5-=carry5<<25;
    carry2=(h2+(long)(1<<25))>>26; h3+=carry2; h2-=carry2<<26;
    carry6=(h6+(long)(1<<25))>>26; h7+=carry6; h6-=carry6<<26;
    carry3=(h3+(long)(1<<24))>>25; h4+=carry3; h3-=carry3<<25;
    carry7=(h7+(long)(1<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry4=(h4+(long)(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry8=(h8+(long)(1<<25))>>26; h9+=carry8; h8-=carry8<<26;
    carry9=(h9+(long)(1<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry0=(h0+(long)(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    h[0]=(int)h0; h[1]=(int)h1; h[2]=(int)h2; h[3]=(int)h3; h[4]=(int)h4;
    h[5]=(int)h5; h[6]=(int)h6; h[7]=(int)h7; h[8]=(int)h8; h[9]=(int)h9;
}

static void fe_sq(fe h, const fe f) {
    int f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4],f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
    int f0_2=2*f0,f1_2=2*f1,f2_2=2*f2,f3_2=2*f3,f4_2=2*f4;
    int f5_2=2*f5,f6_2=2*f6,f7_2=2*f7;
    int f5_38=38*f5,f6_19=19*f6,f7_38=38*f7,f8_19=19*f8,f9_38=38*f9;
    long f0f0=f0*(long)f0, f0f1_2=f0_2*(long)f1, f0f2_2=f0_2*(long)f2;
    long f0f3_2=f0_2*(long)f3, f0f4_2=f0_2*(long)f4, f0f5_2=f0_2*(long)f5;
    long f0f6_2=f0_2*(long)f6, f0f7_2=f0_2*(long)f7, f0f8_2=f0_2*(long)f8;
    long f0f9_2=f0_2*(long)f9;
    long f1f1_2=f1_2*(long)f1, f1f2_2=f1_2*(long)f2, f1f3_4=f1_2*(long)f3_2;
    long f1f4_2=f1_2*(long)f4, f1f5_4=f1_2*(long)f5_2, f1f6_2=f1_2*(long)f6;
    long f1f7_4=f1_2*(long)f7_2, f1f8_2=f1_2*(long)f8, f1f9_76=f1_2*(long)f9_38;
    long f2f2=f2*(long)f2, f2f3_2=f2_2*(long)f3, f2f4_2=f2_2*(long)f4;
    long f2f5_2=f2_2*(long)f5, f2f6_2=f2_2*(long)f6, f2f7_2=f2_2*(long)f7;
    long f2f8_38=f2_2*(long)f8_19, f2f9_38=f2*(long)f9_38;
    long f3f3_2=f3_2*(long)f3, f3f4_2=f3_2*(long)f4, f3f5_4=f3_2*(long)f5_2;
    long f3f6_2=f3_2*(long)f6, f3f7_76=f3_2*(long)f7_38;
    long f3f8_38=f3_2*(long)f8_19, f3f9_76=f3_2*(long)f9_38;
    long f4f4=f4*(long)f4, f4f5_2=f4_2*(long)f5, f4f6_38=f4_2*(long)f6_19;
    long f4f7_38=f4*(long)f7_38, f4f8_38=f4_2*(long)f8_19, f4f9_38=f4*(long)f9_38;
    long f5f5_38=f5*(long)f5_38, f5f6_38=f5_2*(long)f6_19;
    long f5f7_76=f5_2*(long)f7_38, f5f8_38=f5_2*(long)f8_19, f5f9_76=f5_2*(long)f9_38;
    long f6f6_19=f6*(long)f6_19, f6f7_38=f6*(long)f7_38;
    long f6f8_38=f6_2*(long)f8_19, f6f9_38=f6*(long)f9_38;
    long f7f7_38=f7*(long)f7_38, f7f8_38=f7_2*(long)f8_19, f7f9_76=f7_2*(long)f9_38;
    long f8f8_19=f8*(long)f8_19, f8f9_38=f8*(long)f9_38, f9f9_38=f9*(long)f9_38;
    long h0=f0f0+f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
    long h1=f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
    long h2=f0f2_2+f1f1_2+f3f9_76+f4f8_38+f5f7_76+f6f6_19;
    long h3=f0f3_2+f1f2_2+f4f9_38+f5f8_38+f6f7_38;
    long h4=f0f4_2+f1f3_4+f2f2+f5f9_76+f6f8_38+f7f7_38;
    long h5=f0f5_2+f1f4_2+f2f3_2+f6f9_38+f7f8_38;
    long h6=f0f6_2+f1f5_4+f2f4_2+f3f3_2+f7f9_76+f8f8_19;
    long h7=f0f7_2+f1f6_2+f2f5_2+f3f4_2+f8f9_38;
    long h8=f0f8_2+f1f7_4+f2f6_2+f3f5_4+f4f4+f9f9_38;
    long h9=f0f9_2+f1f8_2+f2f7_2+f3f6_2+f4f5_2;
    long carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;
    carry0=(h0+(long)(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    carry4=(h4+(long)(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry1=(h1+(long)(1<<24))>>25; h2+=carry1; h1-=carry1<<25;
    carry5=(h5+(long)(1<<24))>>25; h6+=carry5; h5-=carry5<<25;
    carry2=(h2+(long)(1<<25))>>26; h3+=carry2; h2-=carry2<<26;
    carry6=(h6+(long)(1<<25))>>26; h7+=carry6; h6-=carry6<<26;
    carry3=(h3+(long)(1<<24))>>25; h4+=carry3; h3-=carry3<<25;
    carry7=(h7+(long)(1<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry4=(h4+(long)(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry8=(h8+(long)(1<<25))>>26; h9+=carry8; h8-=carry8<<26;
    carry9=(h9+(long)(1<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry0=(h0+(long)(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    h[0]=(int)h0; h[1]=(int)h1; h[2]=(int)h2; h[3]=(int)h3; h[4]=(int)h4;
    h[5]=(int)h5; h[6]=(int)h6; h[7]=(int)h7; h[8]=(int)h8; h[9]=(int)h9;
}

/* fe_sq2: h = 2*f*f */
static void fe_sq2(fe h, const fe f) {
    fe_sq(h, f);
    /* multiply result by 2 */
    long h0=(long)h[0]*2, h1=(long)h[1]*2, h2=(long)h[2]*2, h3=(long)h[3]*2, h4=(long)h[4]*2;
    long h5=(long)h[5]*2, h6=(long)h[6]*2, h7=(long)h[7]*2, h8=(long)h[8]*2, h9=(long)h[9]*2;
    long carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;
    carry0=(h0+(long)(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    carry4=(h4+(long)(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry1=(h1+(long)(1<<24))>>25; h2+=carry1; h1-=carry1<<25;
    carry5=(h5+(long)(1<<24))>>25; h6+=carry5; h5-=carry5<<25;
    carry2=(h2+(long)(1<<25))>>26; h3+=carry2; h2-=carry2<<26;
    carry6=(h6+(long)(1<<25))>>26; h7+=carry6; h6-=carry6<<26;
    carry3=(h3+(long)(1<<24))>>25; h4+=carry3; h3-=carry3<<25;
    carry7=(h7+(long)(1<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry4=(h4+(long)(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry8=(h8+(long)(1<<25))>>26; h9+=carry8; h8-=carry8<<26;
    carry9=(h9+(long)(1<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry0=(h0+(long)(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    h[0]=(int)h0; h[1]=(int)h1; h[2]=(int)h2; h[3]=(int)h3; h[4]=(int)h4;
    h[5]=(int)h5; h[6]=(int)h6; h[7]=(int)h7; h[8]=(int)h8; h[9]=(int)h9;
}

static void fe_invert(fe out, const fe z) {
    fe t0,t1,t2,t3;
    int i;
    fe_sq(t0,z);
    fe_sq(t1,t0); fe_sq(t1,t1);
    fe_mul(t1,z,t1); fe_mul(t0,t0,t1);
    fe_sq(t2,t0);
    fe_mul(t1,t1,t2);
    fe_sq(t2,t1); for(i=1;i<5;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t2,t1); for(i=1;i<10;i++) fe_sq(t2,t2);
    fe_mul(t2,t2,t1);
    fe_sq(t3,t2); for(i=1;i<20;i++) fe_sq(t3,t3);
    fe_mul(t2,t3,t2);
    fe_sq(t2,t2); for(i=1;i<10;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t2,t1); for(i=1;i<50;i++) fe_sq(t2,t2);
    fe_mul(t2,t2,t1);
    fe_sq(t3,t2); for(i=1;i<100;i++) fe_sq(t3,t3);
    fe_mul(t2,t3,t2);
    fe_sq(t2,t2); for(i=1;i<50;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t1,t1); for(i=1;i<5;i++) fe_sq(t1,t1);
    fe_mul(out,t1,t0);
}

static void fe_pow22523(fe out, const fe z) {
    fe t0,t1,t2;
    int i;
    fe_sq(t0,z);
    fe_sq(t1,t0); fe_sq(t1,t1);
    fe_mul(t1,z,t1); fe_mul(t0,t0,t1);
    fe_sq(t0,t0);
    fe_mul(t0,t1,t0);
    fe_sq(t1,t0); for(i=1;i<5;i++) fe_sq(t1,t1);
    fe_mul(t0,t1,t0);
    fe_sq(t1,t0); for(i=1;i<10;i++) fe_sq(t1,t1);
    fe_mul(t1,t1,t0);
    fe_sq(t2,t1); for(i=1;i<20;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t1,t1); for(i=1;i<10;i++) fe_sq(t1,t1);
    fe_mul(t0,t1,t0);
    fe_sq(t1,t0); for(i=1;i<50;i++) fe_sq(t1,t1);
    fe_mul(t1,t1,t0);
    fe_sq(t2,t1); for(i=1;i<100;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t1,t1); for(i=1;i<50;i++) fe_sq(t1,t1);
    fe_mul(t0,t1,t0);
    fe_sq(t0,t0); fe_sq(t0,t0);
    fe_mul(out,t0,z);
}

/* ============================================================
 * Section C: Point operations (ported from ge.cu)
 *
 * Twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
 * ============================================================ */

typedef struct { fe X; fe Y; fe Z; } ge_p2;
typedef struct { fe X; fe Y; fe Z; fe T; } ge_p3;
typedef struct { fe X; fe Y; fe Z; fe T; } ge_p1p1;
typedef struct { fe yplusx; fe yminusx; fe xy2d; } ge_precomp;
typedef struct { fe YplusX; fe YminusX; fe Z; fe T2d; } ge_cached;

/* ============================================================
 * Section D: Precomputed base point tables
 * (data from precomp_data.h, CUDA qualifiers removed)
 * ============================================================ */
#include "precomp_data_ocl.h"

/* ============================================================
 * (continued) Point operation implementations
 * ============================================================ */

__constant int d2_data[10] = {
    -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199
};

static void ge_p3_0(ge_p3 *h) {
    fe_0(h->X); fe_1(h->Y); fe_1(h->Z); fe_0(h->T);
}

static void ge_p2_0(ge_p2 *h) {
    fe_0(h->X); fe_1(h->Y); fe_1(h->Z);
}

static void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
}

static void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
    fe_mul(r->T, p->X, p->Y);
}

static void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p) {
    fe_copy(r->X, p->X);
    fe_copy(r->Y, p->Y);
    fe_copy(r->Z, p->Z);
}

static void ge_p3_to_cached(ge_cached *r, const ge_p3 *p) {
    fe d2;
    d2[0]=d2_data[0]; d2[1]=d2_data[1]; d2[2]=d2_data[2]; d2[3]=d2_data[3]; d2[4]=d2_data[4];
    d2[5]=d2_data[5]; d2[6]=d2_data[6]; d2[7]=d2_data[7]; d2[8]=d2_data[8]; d2[9]=d2_data[9];
    fe_add(r->YplusX, p->Y, p->X);
    fe_sub(r->YminusX, p->Y, p->X);
    fe_copy(r->Z, p->Z);
    fe_mul(r->T2d, p->T, d2);
}

static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p) {
    fe t0;
    fe_sq(r->X, p->X);
    fe_sq(r->Z, p->Y);
    fe_sq2(r->T, p->Z);
    fe_add(r->Y, p->X, p->Y);
    fe_sq(t0, r->Y);
    fe_add(r->Y, r->Z, r->X);
    fe_sub(r->Z, r->Z, r->X);
    fe_sub(r->X, t0, r->Y);
    fe_sub(r->T, r->T, r->Z);
}

static void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p) {
    ge_p2 q;
    ge_p3_to_p2(&q, p);
    ge_p2_dbl(r, &q);
}

static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q) {
    fe t0;
    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->yplusx);
    fe_mul(r->Y, r->Y, q->yminusx);
    fe_mul(r->T, q->xy2d, p->T);
    fe_add(t0, p->Z, p->Z);
    fe_sub(r->X, r->Z, r->Y);
    fe_add(r->Y, r->Z, r->Y);
    fe_add(r->Z, t0, r->T);
    fe_sub(r->T, t0, r->T);
}

static void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q) {
    fe t0;
    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->yminusx);
    fe_mul(r->Y, r->Y, q->yplusx);
    fe_mul(r->T, q->xy2d, p->T);
    fe_add(t0, p->Z, p->Z);
    fe_sub(r->X, r->Z, r->Y);
    fe_add(r->Y, r->Z, r->Y);
    fe_sub(r->Z, t0, r->T);
    fe_add(r->T, t0, r->T);
}

static void ge_p3_tobytes(uchar *s, const ge_p3 *h) {
    fe recip, x, y;
    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

static uchar ge_equal(char b, char c) {
    uchar ub = (uchar)b;
    uchar uc = (uchar)c;
    uchar x = ub ^ uc;
    ulong y = (ulong)x;
    y -= 1;
    y >>= 63;
    return (uchar)y;
}

static uchar ge_negative(char b) {
    ulong x = (ulong)(long)b;
    x >>= 63;
    return (uchar)x;
}

static void ge_cmov(ge_precomp *t, const ge_precomp *u, uchar b) {
    fe_cmov(t->yplusx, u->yplusx, b);
    fe_cmov(t->yminusx, u->yminusx, b);
    fe_cmov(t->xy2d, u->xy2d, b);
}

/* select: copy base[pos][*] from constant table to private t */
static void ge_select(ge_precomp *t, int pos, char b) {
    ge_precomp minust, tmp;
    uchar bnegative = ge_negative(b);
    uchar babs = (uchar)(b - (((-bnegative) & b) << 1));

    fe_1(t->yplusx);
    fe_1(t->yminusx);
    fe_0(t->xy2d);

    /* Copy each candidate from __constant table to private tmp, then cmov */
    for (int j = 0; j < 8; j++) {
        for (int k = 0; k < 10; k++) {
            tmp.yplusx[k]  = base[pos][j].yplusx[k];
            tmp.yminusx[k] = base[pos][j].yminusx[k];
            tmp.xy2d[k]    = base[pos][j].xy2d[k];
        }
        ge_cmov(t, &tmp, ge_equal((char)(j+1), (char)babs));
    }

    fe_copy(minust.yplusx,  t->yminusx);
    fe_copy(minust.yminusx, t->yplusx);
    fe_neg(minust.xy2d, t->xy2d);
    ge_cmov(t, &minust, bnegative);
}

static void ge_scalarmult_base(ge_p3 *h, const uchar *a) {
    char e[64];
    char carry;
    ge_p1p1 r;
    ge_p2 s;
    ge_precomp t;
    int i;

    for (i = 0; i < 32; i++) {
        e[2*i+0] = (char)((a[i] >> 0) & 15);
        e[2*i+1] = (char)((a[i] >> 4) & 15);
    }
    carry = 0;
    for (i = 0; i < 63; i++) {
        e[i] += carry;
        carry  = (char)(e[i] + 8);
        carry >>= 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;

    ge_p3_0(h);
    for (i = 1; i < 64; i += 2) {
        ge_select(&t, i/2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }
    ge_p3_dbl(&r, h);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p3(h, &r);
    for (i = 0; i < 64; i += 2) {
        ge_select(&t, i/2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }
}

/* ============================================================
 * Section E: SHA-512 (ported from sha512.cu / LibTomCrypt)
 * ============================================================ */

__constant ulong SHA512_K[80] = {
    (ulong)0x428a2f98d728ae22UL, (ulong)0x7137449123ef65cdUL,
    (ulong)0xb5c0fbcfec4d3b2fUL, (ulong)0xe9b5dba58189dbbcUL,
    (ulong)0x3956c25bf348b538UL, (ulong)0x59f111f1b605d019UL,
    (ulong)0x923f82a4af194f9bUL, (ulong)0xab1c5ed5da6d8118UL,
    (ulong)0xd807aa98a3030242UL, (ulong)0x12835b0145706fbeUL,
    (ulong)0x243185be4ee4b28cUL, (ulong)0x550c7dc3d5ffb4e2UL,
    (ulong)0x72be5d74f27b896fUL, (ulong)0x80deb1fe3b1696b1UL,
    (ulong)0x9bdc06a725c71235UL, (ulong)0xc19bf174cf692694UL,
    (ulong)0xe49b69c19ef14ad2UL, (ulong)0xefbe4786384f25e3UL,
    (ulong)0x0fc19dc68b8cd5b5UL, (ulong)0x240ca1cc77ac9c65UL,
    (ulong)0x2de92c6f592b0275UL, (ulong)0x4a7484aa6ea6e483UL,
    (ulong)0x5cb0a9dcbd41fbd4UL, (ulong)0x76f988da831153b5UL,
    (ulong)0x983e5152ee66dfabUL, (ulong)0xa831c66d2db43210UL,
    (ulong)0xb00327c898fb213fUL, (ulong)0xbf597fc7beef0ee4UL,
    (ulong)0xc6e00bf33da88fc2UL, (ulong)0xd5a79147930aa725UL,
    (ulong)0x06ca6351e003826fUL, (ulong)0x142929670a0e6e70UL,
    (ulong)0x27b70a8546d22ffcUL, (ulong)0x2e1b21385c26c926UL,
    (ulong)0x4d2c6dfc5ac42aedUL, (ulong)0x53380d139d95b3dfUL,
    (ulong)0x650a73548baf63deUL, (ulong)0x766a0abb3c77b2a8UL,
    (ulong)0x81c2c92e47edaee6UL, (ulong)0x92722c851482353bUL,
    (ulong)0xa2bfe8a14cf10364UL, (ulong)0xa81a664bbc423001UL,
    (ulong)0xc24b8b70d0f89791UL, (ulong)0xc76c51a30654be30UL,
    (ulong)0xd192e819d6ef5218UL, (ulong)0xd69906245565a910UL,
    (ulong)0xf40e35855771202aUL, (ulong)0x106aa07032bbd1b8UL,
    (ulong)0x19a4c116b8d2d0c8UL, (ulong)0x1e376c085141ab53UL,
    (ulong)0x2748774cdf8eeb99UL, (ulong)0x34b0bcb5e19b48a8UL,
    (ulong)0x391c0cb3c5c95a63UL, (ulong)0x4ed8aa4ae3418acbUL,
    (ulong)0x5b9cca4f7763e373UL, (ulong)0x682e6ff3d6b2b8a3UL,
    (ulong)0x748f82ee5defb2fcUL, (ulong)0x78a5636f43172f60UL,
    (ulong)0x84c87814a1f0ab72UL, (ulong)0x8cc702081a6439ecUL,
    (ulong)0x90befffa23631e28UL, (ulong)0xa4506cebde82bde9UL,
    (ulong)0xbef9a3f7b2c67915UL, (ulong)0xc67178f2e372532bUL,
    (ulong)0xca273eceea26619cUL, (ulong)0xd186b8c721c0c207UL,
    (ulong)0xeada7dd6cde0eb1eUL, (ulong)0xf57d4f7fee6ed178UL,
    (ulong)0x06f067aa72176fbaUL, (ulong)0x0a637dc5a2c898a6UL,
    (ulong)0x113f9804bef90daeUL, (ulong)0x1b710b35131c471bUL,
    (ulong)0x28db77f523047d84UL, (ulong)0x32caab7b40c72493UL,
    (ulong)0x3c9ebe0a15c9bebcUL, (ulong)0x431d67c49c100d4cUL,
    (ulong)0x4cc5d4becb3e42b6UL, (ulong)0x597f299cfc657e2aUL,
    (ulong)0x5fcb6fab3ad6faecUL, (ulong)0x6c44198c4a475817UL
};

#define ROR64(x,y) (((x)>>(y))|((x)<<(64-(y))))
#define STORE64H(x,y) do { \
    (y)[0]=(uchar)(((x)>>56)&255); (y)[1]=(uchar)(((x)>>48)&255); \
    (y)[2]=(uchar)(((x)>>40)&255); (y)[3]=(uchar)(((x)>>32)&255); \
    (y)[4]=(uchar)(((x)>>24)&255); (y)[5]=(uchar)(((x)>>16)&255); \
    (y)[6]=(uchar)(((x)>>8)&255);  (y)[7]=(uchar)((x)&255); } while(0)
#define LOAD64H(x,y) do { \
    x = ((ulong)((y)[0]&255)<<56)|((ulong)((y)[1]&255)<<48)| \
        ((ulong)((y)[2]&255)<<40)|((ulong)((y)[3]&255)<<32)| \
        ((ulong)((y)[4]&255)<<24)|((ulong)((y)[5]&255)<<16)| \
        ((ulong)((y)[6]&255)<<8) |((ulong)((y)[7]&255)); } while(0)
#define Ch(x,y,z)   ((z)^((x)&((y)^(z))))
#define Maj(x,y,z)  ((((x)|(y))&(z))|((x)&(y)))
#define Sigma0(x)   (ROR64(x,28)^ROR64(x,34)^ROR64(x,39))
#define Sigma1(x)   (ROR64(x,14)^ROR64(x,18)^ROR64(x,41))
#define Gamma0(x)   (ROR64(x,1)^ROR64(x,8)^((x)>>7))
#define Gamma1(x)   (ROR64(x,19)^ROR64(x,61)^((x)>>6))

static void sha512_compress(ulong *state, const uchar *buf) {
    ulong S[8], W[80], t0, t1;
    int i;
    for (i = 0; i < 8; i++) S[i] = state[i];
    for (i = 0; i < 16; i++) { LOAD64H(W[i], buf + 8*i); }
    for (i = 16; i < 80; i++)
        W[i] = Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16];
#define RND(a,b,c,d,e,f,g,h,i) \
    t0 = h + Sigma1(e) + Ch(e,f,g) + SHA512_K[i] + W[i]; \
    t1 = Sigma0(a) + Maj(a,b,c); \
    d += t0; h = t0 + t1;
    for (i = 0; i < 80; i += 8) {
        RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i+0);
        RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],i+1);
        RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],i+2);
        RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],i+3);
        RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],i+4);
        RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],i+5);
        RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],i+6);
        RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],i+7);
    }
#undef RND
    for (i = 0; i < 8; i++) state[i] += S[i];
}

/*
 * sha512_32: compute SHA-512 of exactly 32 bytes.
 * Specialized (single-block) version for performance.
 * Output: 64 bytes in `out`.
 */
static void sha512_32(uchar *out, const uchar *seed) {
    ulong state[8];
    uchar buf[128];
    int i;

    /* Initialize state */
    state[0] = (ulong)0x6a09e667f3bcc908UL;
    state[1] = (ulong)0xbb67ae8584caa73bUL;
    state[2] = (ulong)0x3c6ef372fe94f82bUL;
    state[3] = (ulong)0xa54ff53a5f1d36f1UL;
    state[4] = (ulong)0x510e527fade682d1UL;
    state[5] = (ulong)0x9b05688c2b3e6c1fUL;
    state[6] = (ulong)0x1f83d9abfb41bd6bUL;
    state[7] = (ulong)0x5be0cd19137e2179UL;

    /* Build padded block: 32 bytes of data + padding */
    for (i = 0; i < 32; i++) buf[i] = seed[i];
    buf[32] = 0x80;                    /* append bit '1' */
    for (i = 33; i < 120; i++) buf[i] = 0; /* zero padding */
    /* message length = 32 bytes = 256 bits, stored big-endian in last 16 bytes */
    /* high 8 bytes of length (always 0 for 32-byte input) */
    for (i = 112; i < 120; i++) buf[i] = 0;
    /* low 8 bytes: 256 = 0x0000000000000100 */
    STORE64H((ulong)256, buf+120);

    sha512_compress(state, buf);

    /* Output */
    for (i = 0; i < 8; i++) STORE64H(state[i], out + 8*i);
}

/* ============================================================
 * Section F: Ed25519 key derivation
 * ============================================================ */

static void ed25519_derive_pubkey(const uchar *seed, uchar *pubkey) {
    uchar h[64];
    sha512_32(h, seed);
    /* Clamp scalar (RFC 8032) */
    h[0]  &= 248;
    h[31] &= 63;
    h[31] |= 64;
    /* Scalar multiplication */
    ge_p3 A;
    ge_scalarmult_base(&A, h);
    ge_p3_tobytes(pubkey, &A);
}

/* ============================================================
 * Section G: Seed increment (256-bit little-endian counter)
 * ============================================================ */

static void increment_seed(uchar *seed) {
    for (int i = 0; i < 32; i++) {
        if (seed[i] < 255) { seed[i]++; return; }
        seed[i] = 0;
    }
}

/* ============================================================
 * Section H: Main kernel
 *
 * seeds_in:    global_size * 32 bytes (one 32-byte seed per work item,
 *              filled from /dev/urandom on the host)
 * pubkeys_out: global_size * keys_per_item * 32 bytes
 *              (one 32-byte pubkey per generated key)
 * keys_per_item: how many keys each work item generates by
 *              incrementing its seed
 * ============================================================ */

__kernel void ed25519_generate(
    __global const uchar *seeds_in,
    __global uchar *pubkeys_out,
    uint keys_per_item
) {
    uint gid = get_global_id(0);
    uchar seed[32];
    uchar pubkey[32];
    ulong out_off = (ulong)gid * keys_per_item * 32;

    /* Load this work item's seed into private memory */
    ulong seed_off = (ulong)gid * 32;
    for (int j = 0; j < 32; j++) seed[j] = seeds_in[seed_off + j];

    /* Generate keys_per_item keys */
    for (uint k = 0; k < keys_per_item; k++) {
        ed25519_derive_pubkey(seed, pubkey);
        ulong pub_off = out_off + (ulong)k * 32;
        for (int j = 0; j < 32; j++) pubkeys_out[pub_off + j] = pubkey[j];
        increment_seed(seed);
    }
}
