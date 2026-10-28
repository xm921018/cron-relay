(function(nacl) {
'use strict';

// Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
// Public domain.
//
// Implementation derived from TweetNaCl version 20140427.
// See for details: http://tweetnacl.cr.yp.to/

var u64 = function(h, l) { this.hi = h|0 >>> 0; this.lo = l|0 >>> 0; };
var gf = function(init) {
  var i, r = new Float64Array(16);
  if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
  return r;
};

//  Pluggable, initialized in high-level API below.
var randombytes = function(/* x, n */) { throw new Error('no PRNG'); };

var _0 = new Uint8Array(16);
var _9 = new Uint8Array(32); _9[0] = 9;

var gf0 = gf(),
    gf1 = gf([1]),
    _121665 = gf([0xdb41, 1]),
    D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]),
    D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]),
    X = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]),
    Y = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]),
    I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);

function L32(x, c) { return (x << c) | (x >>> (32 - c)); }

function ld32(x, i) {
  var u = x[i+3] & 0xff;
  u = (u<<8)|(x[i+2] & 0xff);
  u = (u<<8)|(x[i+1] & 0xff);
  return (u<<8)|(x[i+0] & 0xff);
}

function dl64(x, i) {
  var h = (x[i] << 24) | (x[i+1] << 16) | (x[i+2] << 8) | x[i+3];
  var l = (x[i+4] << 24) | (x[i+5] << 16) | (x[i+6] << 8) | x[i+7];
  return new u64(h, l);
}

function st32(x, j, u) {
  var i;
  for (i = 0; i < 4; i++) { x[j+i] = u & 255; u >>>= 8; }
}

function ts64(x, i, u) {
  x[i]   = (u.hi >> 24) & 0xff;
  x[i+1] = (u.hi >> 16) & 0xff;
  x[i+2] = (u.hi >>  8) & 0xff;
  x[i+3] = u.hi & 0xff;
  x[i+4] = (u.lo >> 24)  & 0xff;
  x[i+5] = (u.lo >> 16)  & 0xff;
  x[i+6] = (u.lo >>  8)  & 0xff;
  x[i+7] = u.lo & 0xff;
}

function vn(x, xi, y, yi, n) {
  var i,d = 0;
  for (i = 0; i < n; i++) d |= x[xi+i]^y[yi+i];
  return (1 & ((d - 1) >>> 8)) - 1;
}

function crypto_verify_16(x, xi, y, yi) {
  return vn(x,xi,y,yi,16);
}

function crypto_verify_32(x, xi, y, yi) {
  return vn(x,xi,y,yi,32);
}

function core(out,inp,k,c,h) {
  var w = new Uint32Array(16), x = new Uint32Array(16),
      y = new Uint32Array(16), t = new Uint32Array(4);
  var i, j, m;

  for (i = 0; i < 4; i++) {
    x[5*i] = ld32(c, 4*i);
    x[1+i] = ld32(k, 4*i);
    x[6+i] = ld32(inp, 4*i);
    x[11+i] = ld32(k, 16+4*i);
  }

  for (i = 0; i < 16; i++) y[i] = x[i];

  for (i = 0; i < 20; i++) {
    for (j = 0; j < 4; j++) {
      for (m = 0; m < 4; m++) t[m] = x[(5*j+4*m)%16];
      t[1] ^= L32((t[0]+t[3])|0, 7);
      t[2] ^= L32((t[1]+t[0])|0, 9);
      t[3] ^= L32((t[2]+t[1])|0,13);
      t[0] ^= L32((t[3]+t[2])|0,18);
      for (m = 0; m < 4; m++) w[4*j+(j+m)%4] = t[m];
    }
    for (m = 0; m < 16; m++) x[m] = w[m];
  }

  if (h) {
    for (i = 0; i < 16; i++) x[i] = (x[i] + y[i]) | 0;
    for (i = 0; i < 4; i++) {
      x[5*i] = (x[5*i] - ld32(c, 4*i)) | 0;
      x[6+i] = (x[6+i] - ld32(inp, 4*i)) | 0;
    }
    for (i = 0; i < 4; i++) {
      st32(out,4*i,x[5*i]);
      st32(out,16+4*i,x[6+i]);
    }
  } else {
    for (i = 0; i < 16; i++) st32(out, 4 * i, (x[i] + y[i]) | 0);
  }
}

function crypto_core_salsa20(out,inp,k,c) {
  core(out,inp,k,c,false);
  return 0;
}

function crypto_core_hsalsa20(out,inp,k,c) {
  core(out,inp,k,c,true);
  return 0;
}

var sigma = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]);
            // "expand 32-byte k"

function crypto_stream_salsa20_xor(c,cpos,m,mpos,b,n,k) {
  var z = new Uint8Array(16), x = new Uint8Array(64);
  var u, i;
  if (!b) return 0;
  for (i = 0; i < 16; i++) z[i] = 0;
  for (i = 0; i < 8; i++) z[i] = n[i];
  while (b >= 64) {
    crypto_core_salsa20(x,z,k,sigma);
    for (i = 0; i < 64; i++) c[cpos+i] = (m?m[mpos+i]:0) ^ x[i];
    u = 1;
    for (i = 8; i < 16; i++) {
      u = u + (z[i] & 0xff) | 0;
      z[i] = u & 0xff;
      u >>>= 8;
    }
    b -= 64;
    cpos += 64;
    if (m) mpos += 64;
  }
  if (b > 0) {
    crypto_core_salsa20(x,z,k,sigma);
    for (i = 0; i < b; i++) c[cpos+i] = (m?m[mpos+i]:0) ^ x[i];
  }
  return 0;
}

function crypto_stream_salsa20(c,cpos,d,n,k) {
  return crypto_stream_salsa20_xor(c,cpos,null,0,d,n,k);
}

function crypto_stream(c,cpos,d,n,k) {
  var s = new Uint8Array(32);
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20(c,cpos,d,n.subarray(16),s);
}

function crypto_stream_xor(c,cpos,m,mpos,d,n,k) {
  var s = new Uint8Array(32);
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20_xor(c,cpos,m,mpos,d,n.subarray(16),s);
}

function add1305(h, c) {
  var j, u = 0;
  for (j = 0; j < 17; j++) {
    u = (u + ((h[j] + c[j]) | 0)) | 0;
    h[j] = u & 255;
    u >>>= 8;
  }
}

var minusp = new Uint32Array([
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
]);

function crypto_onetimeauth(out, outpos, m, mpos, n, k) {
  var s, i, j, u;
  var x = new Uint32Array(17), r = new Uint32Array(17),
      h = new Uint32Array(17), c = new Uint32Array(17),
      g = new Uint32Array(17);
  for (j = 0; j < 17; j++) r[j]=h[j]=0;
  for (j = 0; j < 16; j++) r[j]=k[j];
  r[3]&=15;
  r[4]&=252;
  r[7]&=15;
  r[8]&=252;
  r[11]&=15;
  r[12]&=252;
  r[15]&=15;

  while (n > 0) {
    for (j = 0; j < 17; j++) c[j] = 0;
    for (j = 0; (j < 16) && (j < n); ++j) c[j] = m[mpos+j];
    c[j] = 1;
    mpos += j; n -= j;
    add1305(h,c);
    for (i = 0; i < 17; i++) {
      x[i] = 0;
      for (j = 0; j < 17; j++) x[i] = (x[i] + (h[j] * ((j <= i) ? r[i - j] : ((320 * r[i + 17 - j])|0))) | 0) | 0;
    }
    for (i = 0; i < 17; i++) h[i] = x[i];
    u = 0;
    for (j = 0; j < 16; j++) {
      u = (u + h[j]) | 0;
      h[j] = u & 255;
      u >>>= 8;
    }
    u = (u + h[16]) | 0; h[16] = u & 3;
    u = (5 * (u >>> 2)) | 0;
    for (j = 0; j < 16; j++) {
      u = (u + h[j]) | 0;
      h[j] = u & 255;
      u >>>= 8;
    }
    u = (u + h[16]) | 0; h[16] = u;
  }

  for (j = 0; j < 17; j++) g[j] = h[j];
  add1305(h,minusp);
  s = (-(h[16] >>> 7) | 0);
  for (j = 0; j < 17; j++) h[j] ^= s & (g[j] ^ h[j]);

  for (j = 0; j < 16; j++) c[j] = k[j + 16];
  c[16] = 0;
  add1305(h,c);
  for (j = 0; j < 16; j++) out[outpos+j] = h[j];
  return 0;
}

function crypto_onetimeauth_verify(h, hpos, m, mpos, n, k) {
  var x = new Uint8Array(16);
  crypto_onetimeauth(x,0,m,mpos,n,k);
  return crypto_verify_16(h,hpos,x,0);
}

function crypto_secretbox(c,m,d,n,k) {
  var i;
  if (d < 32) return -1;
  crypto_stream_xor(c,0,m,0,d,n,k);
  crypto_onetimeauth(c, 16, c, 32, d - 32, c);
  for (i = 0; i < 16; i++) c[i] = 0;
  return 0;
}

function crypto_secretbox_open(m,c,d,n,k) {
  var i;
  var x = new Uint8Array(32);
  if (d < 32) return -1;
  crypto_stream(x,0,32,n,k);
  if (crypto_onetimeauth_verify(c, 16,c, 32,d - 32,x) !== 0) return -1;
  crypto_stream_xor(m,0,c,0,d,n,k);
  for (i = 0; i < 32; i++) m[i] = 0;
  return 0;
}

function set25519(r, a) {
  var i;
  for (i = 0; i < 16; i++) r[i] = a[i]|0;
}

function car25519(o) {
  var c;
  var i;
  for (i = 0; i < 16; i++) {
      o[i] += 65536;
      c = Math.floor(o[i] / 65536);
      o[(i+1)*(i<15?1:0)] += c - 1 + 37 * (c-1) * (i===15?1:0);
      o[i] -= (c * 65536);
  }
}

function sel25519(p, q, b) {
  var t, c = ~(b-1);
  for (var i = 0; i < 16; i++) {
    t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

function pack25519(o, n) {
  var i, j, b;
  var m = gf(), t = gf();
  for (i = 0; i < 16; i++) t[i] = n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for (j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i-1]>>16) & 1);
      m[i-1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14]>>16) & 1);
    b = (m[15]>>16) & 1;
    m[14] &= 0xffff;
    sel25519(t, m, 1-b);
  }
  for (i = 0; i < 16; i++) {
    o[2*i] = t[i] & 0xff;
    o[2*i+1] = t[i]>>8;
  }
}

function neq25519(a, b) {
  var c = new Uint8Array(32), d = new Uint8Array(32);
  pack25519(c, a);
  pack25519(d, b);
  return crypto_verify_32(c, 0, d, 0);
}

function par25519(a) {
  var d = new Uint8Array(32);
  pack25519(d, a);
  return d[0] & 1;
}

function unpack25519(o, n) {
  var i;
  for (i = 0; i < 16; i++) o[i] = n[2*i] + (n[2*i+1] << 8);
  o[15] &= 0x7fff;
}

function A(o, a, b) {
  var i;
  for (i = 0; i < 16; i++) o[i] = (a[i] + b[i])|0;
}

function Z(o, a, b) {
  var i;
  for (i = 0; i < 16; i++) o[i] = (a[i] - b[i])|0;
}

function M(o, a, b) {
  var i, j, t = new Float64Array(31);
  for (i = 0; i < 31; i++) t[i] = 0;
  for (i = 0; i < 16; i++) {
    for (j = 0; j < 16; j++) {
      t[i+j] += a[i] * b[j];
    }
  }
  for (i = 0; i < 15; i++) {
    t[i] += 38 * t[i+16];
  }
  for (i = 0; i < 16; i++) o[i] = t[i];
  car25519(o);
  car25519(o);
}

function S(o, a) {
  M(o, a, a);
}

function inv25519(o, i) {
  var c = gf();
  var a;
  for (a = 0; a < 16; a++) c[a] = i[a];
  for (a = 253; a >= 0; a--) {
    S(c, c);
    if(a !== 2 && a !== 4) M(c, c, i);
  }
  for (a = 0; a < 16; a++) o[a] = c[a];
}

function pow2523(o, i) {
  var c = gf();
  var a;
  for (a = 0; a < 16; a++) c[a] = i[a];
  for (a = 250; a >= 0; a--) {
      S(c, c);
      if(a !== 1) M(c, c, i);
  }
  for (a = 0; a < 16; a++) o[a] = c[a];
}

function crypto_scalarmult(q, n, p) {
  var z = new Uint8Array(32);
  var x = new Float64Array(80), r, i;
  var a = gf(), b = gf(), c = gf(),
      d = gf(), e = gf(), f = gf();
  for (i = 0; i < 31; i++) z[i] = n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  for (i = 0; i < 16; i++) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for (i=254; i>=0; --i) {
    r=(z[i>>>3]>>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  for (i = 0; i < 16; i++) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  var x32 = x.subarray(32);
  var x16 = x.subarray(16);
  inv25519(x32,x32);
  M(x16,x16,x32);
  pack25519(q,x16);
  return 0;
}

function crypto_scalarmult_base(q, n) {
  return crypto_scalarmult(q, n, _9);
}

function crypto_box_keypair(y, x) {
  randombytes(x, 32);
  return crypto_scalarmult_base(y, x);
}

function crypto_box_beforenm(k, y, x) {
  var s = new Uint8Array(32);
  crypto_scalarmult(s, x, y);
  return crypto_core_hsalsa20(k, _0, s, sigma);
}

var crypto_box_afternm = crypto_secretbox;
var crypto_box_open_afternm = crypto_secretbox_open;

function crypto_box(c, m, d, n, y, x) {
  var k = new Uint8Array(32);
  crypto_box_beforenm(k, y, x);
  return crypto_box_afternm(c, m, d, n, k);
}

function crypto_box_open(m, c, d, n, y, x) {
  var k = new Uint8Array(32);
  crypto_box_beforenm(k, y, x);
  return crypto_box_open_afternm(m, c, d, n, k);
}

function add64() {
  var a = 0, b = 0, c = 0, d = 0, m16 = 65535, l, h, i;
  for (i = 0; i < arguments.length; i++) {
    l = arguments[i].lo;
    h = arguments[i].hi;
    a += (l & m16); b += (l >>> 16);
    c += (h & m16); d += (h >>> 16);
  }

  b += (a >>> 16);
  c += (b >>> 16);
  d += (c >>> 16);

  return new u64((c & m16) | (d << 16), (a & m16) | (b << 16));
}

function shr64(x, c) {
  return new u64((x.hi >>> c), (x.lo >>> c) | (x.hi << (32 - c)));
}

function xor64() {
  var l = 0, h = 0, i;
  for (i = 0; i < arguments.length; i++) {
    l ^= arguments[i].lo;
    h ^= arguments[i].hi;
  }
  return new u64(h, l);
}

function R(x, c) {
  var h, l, c1 = 32 - c;
  if (c < 32) {
    h = (x.hi >>> c) | (x.lo << c1);
    l = (x.lo >>> c) | (x.hi << c1);
  } else if (c < 64) {
    h = (x.lo >>> c) | (x.hi << c1);
    l = (x.hi >>> c) | (x.lo << c1);
  }
  return new u64(h, l);
}

function Ch(x, y, z) {
  var h = (x.hi & y.hi) ^ (~x.hi & z.hi),
      l = (x.lo & y.lo) ^ (~x.lo & z.lo);
  return new u64(h, l);
}

function Maj(x, y, z) {
  var h = (x.hi & y.hi) ^ (x.hi & z.hi) ^ (y.hi & z.hi),
      l = (x.lo & y.lo) ^ (x.lo & z.lo) ^ (y.lo & z.lo);
  return new u64(h, l);
}

function Sigma0(x) { return xor64(R(x,28), R(x,34), R(x,39)); }
function Sigma1(x) { return xor64(R(x,14), R(x,18), R(x,41)); }
function sigma0(x) { return xor64(R(x, 1), R(x, 8), shr64(x,7)); }
function sigma1(x) { return xor64(R(x,19), R(x,61), shr64(x,6)); }

var K = [
  new u64(0x428a2f98, 0xd728ae22), new u64(0x71374491, 0x23ef65cd),
  new u64(0xb5c0fbcf, 0xec4d3b2f), new u64(0xe9b5dba5, 0x8189dbbc),
  new u64(0x3956c25b, 0xf348b538), new u64(0x59f111f1, 0xb605d019),
  new u64(0x923f82a4, 0xaf194f9b), new u64(0xab1c5ed5, 0xda6d8118),
  new u64(0xd807aa98, 0xa3030242), new u64(0x12835b01, 0x45706fbe),
  new u64(0x243185be, 0x4ee4b28c), new u64(0x550c7dc3, 0xd5ffb4e2),
  new u64(0x72be5d74, 0xf27b896f), new u64(0x80deb1fe, 0x3b1696b1),
  new u64(0x9bdc06a7, 0x25c71235), new u64(0xc19bf174, 0xcf692694),
  new u64(0xe49b69c1, 0x9ef14ad2), new u64(0xefbe4786, 0x384f25e3),
  new u64(0x0fc19dc6, 0x8b8cd5b5), new u64(0x240ca1cc, 0x77ac9c65),
  new u64(0x2de92c6f, 0x592b0275), new u64(0x4a7484aa, 0x6ea6e483),
  new u64(0x5cb0a9dc, 0xbd41fbd4), new u64(0x76f988da, 0x831153b5),
  new u64(0x983e5152, 0xee66dfab), new u64(0xa831c66d, 0x2db43210),
  new u64(0xb00327c8, 0x98fb213f), new u64(0xbf597fc7, 0xbeef0ee4),
  new u64(0xc6e00bf3, 0x3da88fc2), new u64(0xd5a79147, 0x930aa725),
  new u64(0x06ca6351, 0xe003826f), new u64(0x14292967, 0x0a0e6e70),
  new u64(0x27b70a85, 0x46d22ffc), new u64(0x2e1b2138, 0x5c26c926),
  new u64(0x4d2c6dfc, 0x5ac42aed), new u64(0x53380d13, 0x9d95b3df),
  new u64(0x650a7354, 0x8baf63de), new u64(0x766a0abb, 0x3c77b2a8),
  new u64(0x81c2c92e, 0x47edaee6), new u64(0x92722c85, 0x1482353b),
  new u64(0xa2bfe8a1, 0x4cf10364), new u64(0xa81a664b, 0xbc423001),
  new u64(0xc24b8b70, 0xd0f89791), new u64(0xc76c51a3, 0x0654be30),
  new u64(0xd192e819, 0xd6ef5218), new u64(0xd6990624, 0x5565a910),
  new u64(0xf40e3585, 0x5771202a), new u64(0x106aa070, 0x32bbd1b8),
  new u64(0x19a4c116, 0xb8d2d0c8), new u64(0x1e376c08, 0x5141ab53),
  new u64(0x2748774c, 0xdf8eeb99), new u64(0x34b0bcb5, 0xe19b48a8),
  new u64(0x391c0cb3, 0xc5c95a63), new u64(0x4ed8aa4a, 0xe3418acb),
  new u64(0x5b9cca4f, 0x7763e373), new u64(0x682e6ff3, 0xd6b2b8a3),
  new u64(0x748f82ee, 0x5defb2fc), new u64(0x78a5636f, 0x43172f60),
  new u64(0x84c87814, 0xa1f0ab72), new u64(0x8cc70208, 0x1a6439ec),
  new u64(0x90befffa, 0x23631e28), new u64(0xa4506ceb, 0xde82bde9),
  new u64(0xbef9a3f7, 0xb2c67915), new u64(0xc67178f2, 0xe372532b),
  new u64(0xca273ece, 0xea26619c), new u64(0xd186b8c7, 0x21c0c207),
  new u64(0xeada7dd6, 0xcde0eb1e), new u64(0xf57d4f7f, 0xee6ed178),
  new u64(0x06f067aa, 0x72176fba), new u64(0x0a637dc5, 0xa2c898a6),
  new u64(0x113f9804, 0xbef90dae), new u64(0x1b710b35, 0x131c471b),
  new u64(0x28db77f5, 0x23047d84), new u64(0x32caab7b, 0x40c72493),
  new u64(0x3c9ebe0a, 0x15c9bebc), new u64(0x431d67c4, 0x9c100d4c),
  new u64(0x4cc5d4be, 0xcb3e42b6), new u64(0x597f299c, 0xfc657e2a),
  new u64(0x5fcb6fab, 0x3ad6faec), new u64(0x6c44198c, 0x4a475817)
];

function crypto_hashblocks(x, m, n) {
  var z = [], b = [], a = [], w = [], t, i, j;

  for (i = 0; i < 8; i++) z[i] = a[i] = dl64(x, 8*i);

  var pos = 0;
  while (n >= 128) {
    for (i = 0; i < 16; i++) w[i] = dl64(m, 8*i+pos);
    for (i = 0; i < 80; i++) {
      for (j = 0; j < 8; j++) b[j] = a[j];
      t = add64(a[7], Sigma1(a[4]), Ch(a[4], a[5], a[6]), K[i], w[i%16]);
      b[7] = add64(t, Sigma0(a[0]), Maj(a[0], a[1], a[2]));
      b[3] = add64(b[3], t);
      for (j = 0; j < 8; j++) a[(j+1)%8] = b[j];
      if (i%16 === 15) {
        for (j = 0; j < 16; j++) {
          w[j] = add64(w[j], w[(j+9)%16], sigma0(w[(j+1)%16]), sigma1(w[(j+14)%16]));
        }
      }
    }

    for (i = 0; i < 8; i++) {
      a[i] = add64(a[i], z[i]);
      z[i] = a[i];
    }

    pos += 128;
    n -= 128;
  }

  for (i = 0; i < 8; i++) ts64(x, 8*i, z[i]);
  return n;
}

var iv = new Uint8Array([
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
]);

function crypto_hash(out, m, n) {
  var h = new Uint8Array(64), x = new Uint8Array(256);
  var i, b = n;

  for (i = 0; i < 64; i++) h[i] = iv[i];

  crypto_hashblocks(h, m, n);
  n %= 128;

  for (i = 0; i < 256; i++) x[i] = 0;
  for (i = 0; i < n; i++) x[i] = m[b-n+i];
  x[n] = 128;

  n = 256-128*(n<112?1:0);
  x[n-9] = 0;
  ts64(x, n-8, new u64((b / 0x20000000) | 0, b << 3));
  crypto_hashblocks(h, x, n);

  for (i = 0; i < 64; i++) out[i] = h[i];

  return 0;
}

function add(p, q) {
  var a = gf(), b = gf(), c = gf(),
      d = gf(), e = gf(), f = gf(),
      g = gf(), h = gf(), t = gf();

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

function cswap(p, q, b) {
  var i;
  for (i = 0; i < 4; i++) {
    sel25519(p[i], q[i], b);
  }
}

function pack(r, p) {
  var tx = gf(), ty = gf(), zi = gf();
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

function scalarmult(p, q, s) {
  var b, i;
  set25519(p[0], gf0);
  set25519(p[1], gf1);
  set25519(p[2], gf1);
  set25519(p[3], gf0);
  for (i = 255; i >= 0; --i) {
    b = (s[(i/8)|0] >> (i&7)) & 1;
    cswap(p, q, b);
    add(q, p);
    add(p, p);
    cswap(p, q, b);
  }
}

function scalarbase(p, s) {
  var q = [gf(), gf(), gf(), gf()];
  set25519(q[0], X);
  set25519(q[1], Y);
  set25519(q[2], gf1);
  M(q[3], X, Y);
  scalarmult(p, q, s);
}

function crypto_sign_keypair(pk, sk, seeded) {
  var d = new Uint8Array(64);
  var p = [gf(), gf(), gf(), gf()];
  var i;

  if (!seeded) randombytes(sk, 32);
  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p, d);
  pack(pk, p);

  for (i = 0; i < 32; i++) sk[i+32] = pk[i];
  return 0;
}

var L = new Float64Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);

function modL(r, x) {
  var carry, i, j, k;
  for (i = 63; i >= 32; --i) {
    carry = 0;
    for (j = i - 32, k = i - 12; j < k; ++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = Math.floor((x[j] + 128) / 256);
      x[j] -= carry * 256;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (j = 0; j < 32; j++) x[j] -= carry * L[j];
  for (i = 0; i < 32; i++) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

function reduce(r) {
  var x = new Float64Array(64), i;
  for (i = 0; i < 64; i++) x[i] = r[i];
  for (i = 0; i < 64; i++) r[i] = 0;
  modL(r, x);
}

// Note: difference from C - smlen returned, not passed as argument.
function crypto_sign(sm, m, n, sk) {
  var d = new Uint8Array(64), h = new Uint8Array(64), r = new Uint8Array(64);
  var i, j, x = new Float64Array(64);
  var p = [gf(), gf(), gf(), gf()];

  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  var smlen = n + 64;
  for (i = 0; i < n; i++) sm[64 + i] = m[i];
  for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];

  crypto_hash(r, sm.subarray(32), n+32);
  reduce(r);
  scalarbase(p, r);
  pack(sm, p);

  for (i = 32; i < 64; i++) sm[i] = sk[i];
  crypto_hash(h, sm, n + 64);
  reduce(h);

  for (i = 0; i < 64; i++) x[i] = 0;
  for (i = 0; i < 32; i++) x[i] = r[i];
  for (i = 0; i < 32; i++) {
    for (j = 0; j < 32; j++) {
      x[i+j] += h[i] * d[j];
    }
  }

  modL(sm.subarray(32), x);
  return smlen;
}

function unpackneg(r, p) {
  var t = gf(), chk = gf(), num = gf(),
      den = gf(), den2 = gf(), den4 = gf(),
      den6 = gf();

  set25519(r[2], gf1);
  unpack25519(r[1], p);
  S(num, r[1]);
  M(den, num, D);
  Z(num, num, r[2]);
  A(den, r[2], den);

  S(den2, den);
  S(den4, den2);
  M(den6, den4, den2);
  M(t, den6, num);
  M(t, t, den);

  pow2523(t, t);
  M(t, t, num);
  M(t, t, den);
  M(t, t, den);
  M(r[0], t, den);

  S(chk, r[0]);
  M(chk, chk, den);
  if (neq25519(chk, num)) M(r[0], r[0], I);

  S(chk, r[0]);
  M(chk, chk, den);
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) === (p[31]>>7)) Z(r[0], gf0, r[0]);

  M(r[3], r[0], r[1]);
  return 0;
}

function crypto_sign_open(m, sm, n, pk) {
  var i;
  var t = new Uint8Array(32), h = new Uint8Array(64);
  var p = [gf(), gf(), gf(), gf()],
      q = [gf(), gf(), gf(), gf()];

  if (n < 64) return -1;

  if (unpackneg(q, pk)) return -1;

  for (i = 0; i < n; i++) m[i] = sm[i];
  for (i = 0; i < 32; i++) m[i+32] = pk[i];
  crypto_hash(h, m, n);
  reduce(h);
  scalarmult(p, q, h);

  scalarbase(q, sm.subarray(32));
  add(p, q);
  pack(t, p);

  n -= 64;
  if (crypto_verify_32(sm, 0, t, 0)) {
    for (i = 0; i < n; i++) m[i] = 0;
    return -1;
  }

  for (i = 0; i < n; i++) m[i] = sm[i + 64];
  return n;
}

var crypto_secretbox_KEYBYTES = 32,
    crypto_secretbox_NONCEBYTES = 24,
    crypto_secretbox_ZEROBYTES = 32,
    crypto_secretbox_BOXZEROBYTES = 16,
    crypto_scalarmult_BYTES = 32,
    crypto_scalarmult_SCALARBYTES = 32,
    crypto_box_PUBLICKEYBYTES = 32,
    crypto_box_SECRETKEYBYTES = 32,
    crypto_box_BEFORENMBYTES = 32,
    crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES,
    crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES,
    crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES,
    crypto_sign_BYTES = 64,
    crypto_sign_PUBLICKEYBYTES = 32,
    crypto_sign_SECRETKEYBYTES = 64,
    crypto_sign_SEEDBYTES = 32,
    crypto_hash_BYTES = 64;

nacl.lowlevel = {
  crypto_core_hsalsa20: crypto_core_hsalsa20,
  crypto_stream_xor: crypto_stream_xor,
  crypto_stream: crypto_stream,
  crypto_stream_salsa20_xor: crypto_stream_salsa20_xor,
  crypto_stream_salsa20: crypto_stream_salsa20,
  crypto_onetimeauth: crypto_onetimeauth,
  crypto_onetimeauth_verify: crypto_onetimeauth_verify,
  crypto_verify_16: crypto_verify_16,
  crypto_verify_32: crypto_verify_32,
  crypto_secretbox: crypto_secretbox,
  crypto_secretbox_open: crypto_secretbox_open,
  crypto_scalarmult: crypto_scalarmult,
  crypto_scalarmult_base: crypto_scalarmult_base,
  crypto_box_beforenm: crypto_box_beforenm,
  crypto_box_afternm: crypto_box_afternm,
  crypto_box: crypto_box,
  crypto_box_open: crypto_box_open,
  crypto_box_keypair: crypto_box_keypair,
  crypto_hash: crypto_hash,
  crypto_sign: crypto_sign,
  crypto_sign_keypair: crypto_sign_keypair,
  crypto_sign_open: crypto_sign_open,

  crypto_secretbox_KEYBYTES: crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES: crypto_secretbox_NONCEBYTES,
  crypto_secretbox_ZEROBYTES: crypto_secretbox_ZEROBYTES,
  crypto_secretbox_BOXZEROBYTES: crypto_secretbox_BOXZEROBYTES,
  crypto_scalarmult_BYTES: crypto_scalarmult_BYTES,
  crypto_scalarmult_SCALARBYTES: crypto_scalarmult_SCALARBYTES,
  crypto_box_PUBLICKEYBYTES: crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES: crypto_box_SECRETKEYBYTES,
  crypto_box_BEFORENMBYTES: crypto_box_BEFORENMBYTES,
  crypto_box_NONCEBYTES: crypto_box_NONCEBYTES,
  crypto_box_ZEROBYTES: crypto_box_ZEROBYTES,
  crypto_box_BOXZEROBYTES: crypto_box_BOXZEROBYTES,
  crypto_sign_BYTES: crypto_sign_BYTES,
  crypto_sign_PUBLICKEYBYTES: crypto_sign_PUBLICKEYBYTES,
  crypto_sign_SECRETKEYBYTES: crypto_sign_SECRETKEYBYTES,
  crypto_sign_SEEDBYTES: crypto_sign_SEEDBYTES,
  crypto_hash_BYTES: crypto_hash_BYTES,

  gf: gf,
  D: D,
  L: L,
  pack25519: pack25519,
  unpack25519: unpack25519,
  M: M,
  A: A,
  S: S,
  Z: Z,
  pow2523: pow2523,
  add: add,
  set25519: set25519,
  modL: modL,
  scalarmult: scalarmult,
  scalarbase: scalarbase,
};

/* High-level API */

function checkLengths(k, n) {
  if (k.length !== crypto_secretbox_KEYBYTES) throw new Error('bad key size');
  if (n.length !== crypto_secretbox_NONCEBYTES) throw new Error('bad nonce size');
}

function checkBoxLengths(pk, sk) {
  if (pk.length !== crypto_box_PUBLICKEYBYTES) throw new Error('bad public key size');
  if (sk.length !== crypto_box_SECRETKEYBYTES) throw new Error('bad secret key size');
}

function checkArrayTypes() {
  for (var i = 0; i < arguments.length; i++) {
    if (!(arguments[i] instanceof Uint8Array))
      throw new TypeError('unexpected type, use Uint8Array');
  }
}

function cleanup(arr) {
  for (var i = 0; i < arr.length; i++) arr[i] = 0;
}

nacl.randomBytes = function(n) {
  var b = new Uint8Array(n);
  randombytes(b, n);
  return b;
};

nacl.secretbox = function(msg, nonce, key) {
  checkArrayTypes(msg, nonce, key);
  checkLengths(key, nonce);
  var m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.length);
  var c = new Uint8Array(m.length);
  for (var i = 0; i < msg.length; i++) m[i+crypto_secretbox_ZEROBYTES] = msg[i];
  crypto_secretbox(c, m, m.length, nonce, key);
  return c.subarray(crypto_secretbox_BOXZEROBYTES);
};

nacl.secretbox.open = function(box, nonce, key) {
  checkArrayTypes(box, nonce, key);
  checkLengths(key, nonce);
  var c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.length);
  var m = new Uint8Array(c.length);
  for (var i = 0; i < box.length; i++) c[i+crypto_secretbox_BOXZEROBYTES] = box[i];
  if (c.length < 32) return null;
  if (crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) return null;
  return m.subarray(crypto_secretbox_ZEROBYTES);
};

nacl.secretbox.keyLength = crypto_secretbox_KEYBYTES;
nacl.secretbox.nonceLength = crypto_secretbox_NONCEBYTES;
nacl.secretbox.overheadLength = crypto_secretbox_BOXZEROBYTES;

nacl.scalarMult = function(n, p) {
  checkArrayTypes(n, p);
  if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
  if (p.length !== crypto_scalarmult_BYTES) throw new Error('bad p size');
  var q = new Uint8Array(crypto_scalarmult_BYTES);
  crypto_scalarmult(q, n, p);
  return q;
};

nacl.scalarMult.base = function(n) {
  checkArrayTypes(n);
  if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
  var q = new Uint8Array(crypto_scalarmult_BYTES);
  crypto_scalarmult_base(q, n);
  return q;
};

nacl.scalarMult.scalarLength = crypto_scalarmult_SCALARBYTES;
nacl.scalarMult.groupElementLength = crypto_scalarmult_BYTES;

nacl.box = function(msg, nonce, publicKey, secretKey) {
  var k = nacl.box.before(publicKey, secretKey);
  return nacl.secretbox(msg, nonce, k);
};

nacl.box.before = function(publicKey, secretKey) {
  checkArrayTypes(publicKey, secretKey);
  checkBoxLengths(publicKey, secretKey);
  var k = new Uint8Array(crypto_box_BEFORENMBYTES);
  crypto_box_beforenm(k, publicKey, secretKey);
  return k;
};

nacl.box.after = nacl.secretbox;

nacl.box.open = function(msg, nonce, publicKey, secretKey) {
  var k = nacl.box.before(publicKey, secretKey);
  return nacl.secretbox.open(msg, nonce, k);
};

nacl.box.open.after = nacl.secretbox.open;

nacl.box.keyPair = function() {
  var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
  var sk = new Uint8Array(crypto_box_SECRETKEYBYTES);
  crypto_box_keypair(pk, sk);
  return {publicKey: pk, secretKey: sk};
};

nacl.box.keyPair.fromSecretKey = function(secretKey) {
  checkArrayTypes(secretKey);
  if (secretKey.length !== crypto_box_SECRETKEYBYTES)
    throw new Error('bad secret key size');
  var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
  crypto_scalarmult_base(pk, secretKey);
  return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
};

nacl.box.publicKeyLength = crypto_box_PUBLICKEYBYTES;
nacl.box.secretKeyLength = crypto_box_SECRETKEYBYTES;
nacl.box.sharedKeyLength = crypto_box_BEFORENMBYTES;
nacl.box.nonceLength = crypto_box_NONCEBYTES;
nacl.box.overheadLength = nacl.secretbox.overheadLength;

nacl.sign = function(msg, secretKey) {
  checkArrayTypes(msg, secretKey);
  if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
    throw new Error('bad secret key size');
  var signedMsg = new Uint8Array(crypto_sign_BYTES+msg.length);
  crypto_sign(signedMsg, msg, msg.length, secretKey);
  return signedMsg;
};

nacl.sign.open = function(signedMsg, publicKey) {
  checkArrayTypes(signedMsg, publicKey);
  if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
    throw new Error('bad public key size');
  var tmp = new Uint8Array(signedMsg.length);
  var mlen = crypto_sign_open(tmp, signedMsg, signedMsg.length, publicKey);
  if (mlen < 0) return null;
  var m = new Uint8Array(mlen);
  for (var i = 0; i < m.length; i++) m[i] = tmp[i];
  return m;
};

nacl.sign.detached = function(msg, secretKey) {
  var signedMsg = nacl.sign(msg, secretKey);
  var sig = new Uint8Array(crypto_sign_BYTES);
  for (var i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
  return sig;
};

nacl.sign.detached.verify = function(msg, sig, publicKey) {
  checkArrayTypes(msg, sig, publicKey);
  if (sig.length !== crypto_sign_BYTES)
    throw new Error('bad signature size');
  if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
    throw new Error('bad public key size');
  var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
  var m = new Uint8Array(crypto_sign_BYTES + msg.length);
  var i;
  for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
  for (i = 0; i < msg.length; i++) sm[i+crypto_sign_BYTES] = msg[i];
  return (crypto_sign_open(m, sm, sm.length, publicKey) >= 0);
};

nacl.sign.keyPair = function() {
  var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
  var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
  crypto_sign_keypair(pk, sk);
  return {publicKey: pk, secretKey: sk};
};

nacl.sign.keyPair.fromSecretKey = function(secretKey) {
  checkArrayTypes(secretKey);
  if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
    throw new Error('bad secret key size');
  var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
  for (var i = 0; i < pk.length; i++) pk[i] = secretKey[32+i];
  return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
};

nacl.sign.keyPair.fromSeed = function(seed) {
  checkArrayTypes(seed);
  if (seed.length !== crypto_sign_SEEDBYTES)
    throw new Error('bad seed size');
  var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
  var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
  for (var i = 0; i < 32; i++) sk[i] = seed[i];
  crypto_sign_keypair(pk, sk, true);
  return {publicKey: pk, secretKey: sk};
};

nacl.sign.publicKeyLength = crypto_sign_PUBLICKEYBYTES;
nacl.sign.secretKeyLength = crypto_sign_SECRETKEYBYTES;
nacl.sign.seedLength = crypto_sign_SEEDBYTES;
nacl.sign.signatureLength = crypto_sign_BYTES;

nacl.hash = function(msg) {
  checkArrayTypes(msg);
  var h = new Uint8Array(crypto_hash_BYTES);
  crypto_hash(h, msg, msg.length);
  return h;
};

nacl.hash.hashLength = crypto_hash_BYTES;

nacl.verify = function(x, y) {
  checkArrayTypes(x, y);
  // Zero length arguments are considered not equal.
  if (x.length === 0 || y.length === 0) return false;
  if (x.length !== y.length) return false;
  return (vn(x, 0, y, 0, x.length) === 0) ? true : false;
};

nacl.setPRNG = function(fn) {
  randombytes = fn;
};

(function() {
  // Initialize PRNG if environment provides CSPRNG.
  // If not, methods calling randombytes will throw.
  var crypto = typeof self !== 'undefined' ? (self.crypto || self.msCrypto) : null;
  if (crypto && crypto.getRandomValues) {
    // Browsers.
    var QUOTA = 65536;
    nacl.setPRNG(function(x, n) {
      var i, v = new Uint8Array(n);
      for (i = 0; i < n; i += QUOTA) {
        crypto.getRandomValues(v.subarray(i, i + Math.min(n - i, QUOTA)));
      }
      for (i = 0; i < n; i++) x[i] = v[i];
      cleanup(v);
    });
  } else if (typeof require !== 'undefined') {
    // Node.js.
    crypto = require('crypto');
    if (crypto && crypto.randomBytes) {
      nacl.setPRNG(function(x, n) {
        var i, v = crypto.randomBytes(n);
        for (i = 0; i < n; i++) x[i] = v[i];
        cleanup(v);
      });
    }
  }
})();

})(typeof module !== 'undefined' && module.exports ? module.exports : (self.nacl = self.nacl || {}));


// Cloudflare Worker —— 成员自助接入。
// 主通道：手机 + 短信验证码登录网易云 → 拿 MUSIC_U。
// 手动登记：成员直接粘贴浏览器里的 MUSIC_U（短信收不到 / 登录失败时用）。
// 两通道都：解析分享链接拿 song id → 用 KV 维护主号池 → 重算分片 → 覆盖写 GitHub Secrets(NB_POOL_1..5)。
// 需要的 CF 环境变量/绑定：
//   GH_TOKEN   有 repo 权限的 GitHub PAT（写 secret 用，仅服务端，不落前端）
//   GH_OWNER   仓库 owner（如 xm921018）
//   GH_REPO    仓库名（如 cron-relay）
//   GROUP_PASS 管理暗号（2026-10-20 起登记接口不再校验，仅供 /api/resync、/api/report_dead 两个隐藏管理接口）
//   POOL_LIMIT_G1 一群登记上限（默认 500，2026-10-21 由 200 上调）。二群已独立为 dingzhi 系统（自带 500 上限），
//                 主 worker 不再使用 GROUP_PASS2 / POOL_LIMIT_G2（cfg 中保留仅为兼容 stats 字段）
//   POOL       KV namespace 绑定（维护主号池，cookie 不落 GitHub 仓库文件）
// 注意：cookie 只在 KV 与 GitHub Secrets（加密）中存在，仓库文件无明文。


const BASE = 'https://music.163.com';
const NONCE = '0CoJUm6Qyw8W8jud';
const SECRET = 'TA3YiYCfY2dDJQgg';
const VI = '0102030405060708';
const ENCSEC = '84ca47bca10bad09a6b04c5c927ef077d9b9f1e37098aa3eac6ea70eb59df0aa28b691b7e75e4f1f9831754919ea784c8f74fbfadf2898b0be17849fd656060162857830e241aba44991601f137624094c114ea8d17bce815b0cd4e5b8e2fbaba978c6d1d14dc3d1faf852bdd28818031ccdaaa13a6018e1024e2aae98844210';

const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148';

// ---- base64 ----
const b64enc = (u8) => btoa(String.fromCharCode(...new Uint8Array(u8)));
const b64dec = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const utf8 = (s) => new TextEncoder().encode(s);

// ---- AES-CBC (WebCrypto) ----
async function aesCbc(dataU8, keyStr) {
  const key = await crypto.subtle.importKey('raw', utf8(keyStr), { name: 'AES-CBC' }, false, ['encrypt']);
  const n = 16 - dataU8.length % 16;
  const pad = new Uint8Array(dataU8.length + n);
  pad.set(dataU8); pad.fill(n, dataU8.length);
  const ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: utf8(VI) }, key, pad);
  return new Uint8Array(ct);
}
// weapi 标准实现（2026-10-10 实测修复）：
//   json → AES(NONCE) → base64 → AES(随机16字符key) → base64 = params
//   encSecKey = RSA(随机key 反转后按 ASCII 转 hex, e=010001) 转 hex 补零到 256 位
// 旧实现漏了中间 base64 且 encSecKey 固定不匹配，导致网易解不开、返回空 200。
const RSA_MODULUS = '00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7';
function modPow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
async function weapi(data) {
  const chars = '0123456789abcdef';
  const rnd = [...crypto.getRandomValues(new Uint8Array(16))].map(x => chars[x % 16]).join('');
  let p = await aesCbc(utf8(JSON.stringify(data)), NONCE);
  p = b64enc(p);
  p = await aesCbc(utf8(p), rnd);
  const rev = rnd.split('').reverse().join('');
  const hexOfAscii = [...rev].map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  const encSecKey = modPow(BigInt('0x' + hexOfAscii), 0x10001n, BigInt('0x' + RSA_MODULUS)).toString(16).padStart(256, '0');
  return { params: b64enc(p), encSecKey };
}

// 校验一个 MUSIC_U 是否还活着（手动登记即时反馈）
// 策略：重试 2 次；若网易接口不可达（网络/非 JSON 响应）且 cookie 形状合法，降级放行（provisional），
// 交由次日 Actions 的 login_by_cookie 复验，失效号会被 /api/report_dead 自动清理。
async function validateCookie(musicU) {
  const ck = 'MUSIC_U=' + musicU;
  let lastDiag = '';
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      // 普通接口（非 weapi）：带 cookie 直接查账号，2026-10-10 实测返回 JSON
      const r = await fetch(`${BASE}/api/nuser/account/get`, {
        method: 'GET',
        headers: { 'User-Agent': UA, Referer: BASE + '/', 'Cookie': ck },
      });
      const txt = await r.text();
      let j = null;
      try { j = JSON.parse(txt); } catch (e) {}
      if (j && j.code === 200 && (j.profile || {}).userId) return { ok: true, uid: j.profile.userId };
      if (j) return { ok: false, msg: 'MUSIC_U 无效或已失效（code=' + j.code + '，请重新从浏览器复制）' };
      lastDiag = 'HTTP ' + r.status + '，响应非 JSON：' + txt.slice(0, 60);
    } catch (e) {
      lastDiag = '网络异常：' + ((e && e.message) || e);
    }
    if (attempt < 2) await new Promise(res => setTimeout(res, 800));
  }
  if (/^[0-9a-fA-F]{80,}$/.test(musicU)) {
    const hex = [...blake2b(utf8(musicU), 6)].map(b => b.toString(16).padStart(2, '0')).join('');
    return { ok: true, uid: Number('0x' + hex.slice(0, 12)) % 1e12, provisional: true, diag: lastDiag };
  }
  return { ok: false, msg: '校验失败：' + lastDiag + '；且 cookie 形状不对，请重新从浏览器复制 MUSIC_U' };
}

async function resolveSong(link) {
  // 容错：成员经常把 APP 分享的整段文字（带歌名/emoji/@）直接粘进来，先提取出里面的第一个 URL
  const picked = link.match(/https?:\/\/[^\s"'《》<>，,）)】]+/);
  let url = (picked ? picked[0] : link).trim();
  // 先在【原链接】上提取 id：网易云 APP 分享出来的单曲链接是 SPA 格式
  // music.163.com/#/song?id=xxx，井号后是 URL fragment，HTTP 请求不发送 fragment，
  // fetch 之后的 r.url 会把 id 一起丢掉，所以必须在 fetch 之前匹配
  // （网页版复制的 song?id= 格式、短链重定向后的 URL 同样兼容）
  let m = url.match(/[?&]id=(\d+)/);
  // 只收单曲：歌单/专辑/电台/节目/排行榜链接一律拒绝（防一个链接带出整张歌单）
  const COLLECT = /\/(playlist|album|radio|program|toplist)\b/i;
  if (COLLECT.test(url)) {
    return { ok: false, msg: '不支持歌单/专辑等合集链接（一个歌单曲目太多）。请在网易云 APP 里打开【其中一首歌】→ 点分享 → 复制链接，只登记单曲' };
  }
  try {
    const r = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': UA } });
    url = r.url;
  } catch (e) {}
  if (COLLECT.test(url)) {
    return { ok: false, msg: '不支持歌单/专辑等合集链接（一个歌单曲目太多）。请在网易云 APP 里打开【其中一首歌】→ 点分享 → 复制链接，只登记单曲' };
  }
  // 原链接没带 id（如 163cn.tv 短链）时，用跟随重定向后的 r.url 兜底匹配一次
  if (!m) m = url.match(/[?&]id=(\d+)/);
  if (!m) return { ok: false, msg: '链接里没找到歌曲 id：识别到 ' + url.slice(0, 80) + '。请在网易云 APP 里点「分享→复制链接」，把 http 开头的完整链接粘过来' };
  // 双保险：调网易歌曲详情接口确认这个 id 确实是一首歌（防歌单/电台 id 伪装混入）
  try {
    const r = await fetch(`${BASE}/api/song/detail?id=${m[1]}&ids=%5B${m[1]}%5D`, { headers: { 'User-Agent': UA, Referer: BASE + '/' } });
    const j = await r.json();
    if (!j || !Array.isArray(j.songs) || !j.songs.length) {
      return { ok: false, msg: '这个链接不是单曲（可能是歌单/电台/专辑 id）。请分享【单曲】：APP 里播放那首歌 → 分享 → 复制链接' };
    }
  } catch (e) {
    // 详情接口偶发异常时放行（歌单类 URL 已在上面被路径检查拦截）
  }
  return { ok: true, song: Number(m[1]) };
}

// ---- GitHub Secrets（sealed box） ----
// GH_TOKEN / GROUP_PASS 存于 KV（加密、不落仓库、不暴露给前端），运行时从 POOL 读取。
// 这样无需 Cloudflare Secret 权限即可配置，且 GitHub PAT 也不会进公开仓库文件。
let _cfg, _cfgAt = 0;
// KV 值防御性清洗：防止当初写入口令/token 时把 JSON 引号/空白一起存进去
const cleanKV = s => (s || '').trim().replace(/^"+|"+$/g, '');
async function cfg() {
  // 带 5 分钟 TTL 的缓存（2026-10-13 修复：此前永久缓存，KV 里轮换 GH_TOKEN/群口令后
  // 要等 isolate 重启才生效）
  if (!_cfg || Date.now() - _cfgAt > 300000) {
    // 2026-10-23：原来这里是 8 个串行 await（每个都是一次 KV get），冷启动时白白叠加 8 次 rtt。
    // 改成一次并发读取；语义完全不变（同样的键、同样的默认值、同样的 5 分钟缓存）。
    const [ghToken, groupPass, groupPass2, adminPass, assignPass, lim, limG1, limG2] = await Promise.all([
      POOL.get('GH_TOKEN').catch(() => null),
      POOL.get('GROUP_PASS').catch(() => null),
      POOL.get('GROUP_PASS2').catch(() => null),
      POOL.get('ADMIN_PASS').catch(() => null),
      // 分配接口独立口令（2026-10-22）：/api/assign 会下发明文 CK，绝不能用发给全体成员的群口令，
      // 否则任何成员循环 job=0..N 就能把全池 MUSIC_U 拖走。未配置时该接口直接拒绝服务。
      POOL.get('ASSIGN_PASS').catch(() => null),
      POOL.get('POOL_LIMIT').catch(() => null),
      POOL.get('POOL_LIMIT_G1').catch(() => null),
      POOL.get('POOL_LIMIT_G2').catch(() => null),
    ]);
    _cfg = {
      ghToken: cleanKV(ghToken),
      groupPass: cleanKV(groupPass),
      groupPass2: cleanKV(groupPass2),
      adminPass: cleanKV(adminPass),
      assignPass: cleanKV(assignPass),
      // 分群上限：2026-10-22 默认 500 → 1500，同日晚按「20 并发 + 24h 排队上限」下调到 1200
      // （KV 里 POOL_LIMIT_G1 / POOL_LIMIT_G2 仍可覆盖，改数字即时生效不用改代码）
      poolLimit: parseInt(cleanKV(lim), 10) || 1200,
      poolLimitG1: parseInt(cleanKV(limG1), 10) || 1200,
      poolLimitG2: parseInt(cleanKV(limG2), 10) || 500,
      owner: GH_OWNER,
      repo: GH_REPO,
    };
    _cfgAt = Date.now();
  }
  return _cfg;
}
const GH = async () => { const c = await cfg(); return { token: c.ghToken, owner: c.owner, repo: c.repo }; };
// ---- 群口令校验（GROUP_PASS）----
// 二群已独立（dingzhi 系统），主 worker 只认一群口令；带 group:2 的历史请求也按一群口令校验。
function groupPassCheck(c, body) {
  // 2026-10-20 应用户要求去掉一群群口令：恒放行（定制版 dingzhi 本就恒放行，两边一致）。
  // ⚠️ 文件末尾两个隐藏管理接口（/api/resync、/api/report_dead）用的是行内
  //    body.pass !== c.groupPass 校验，千万别改成走本函数，否则管理接口会对外敞开。
  return { ok: true };
}
// 危险管理接口的口令校验（2026-10-26 收紧）。
// 背景：/api/report_dead 能按名单删号（带 confirm 直接删）、/api/resync 能强制重推 12 个 Secrets，
// 而它们原来只认 GROUP_PASS —— 这个口令是发给全体成员的，还硬编码在号池管理工具/CK助手/安卓里，
// 等于半公开：任何群成员一个 POST 就能清空号池。
// 新口径：只要 KV 配了 ADMIN_PASS，这两个接口就【只】认 ADMIN_PASS；没配时才退回群口令（老部署兼容）。
function adminPassOk(c, pass) {
  const p = String(pass || '');
  if (c.adminPass) return p === c.adminPass;
  return !!(c.groupPass && p === c.groupPass);
}
// 跨群对穿口令（2026-10-26）：KV 键 PEER_KEY，两群存同一个 32 位随机值。
// 背景：对穿原来直接复用两边的群口令（dz 的 PEER_PASS 就是 hz 的 music2026），
// 于是「群口令」既能登记、又能读对端全池（含邮箱）、还能删改号。
// 新口径：配了 PEER_KEY 就只认它，完全不再接受群口令；没配时才退回旧的 PEER_PASS 对穿。
async function peerKey() { return cleanKV(await POOL.get('PEER_KEY')); }
async function peerPassOk(pass) {
  const k = await peerKey();
  const p = String(pass || '');
  if (k) return p === k;
  const old = cleanKV(await POOL.get('PEER_PASS'));
  return !!(old && p === old);
}
// ---- 分群计数辅助：历史条目没有 grp 字段的一律算一群 ----
const grpOf = e => (Number(e && e.grp) === 2 ? 2 : 1);
const groupLimitOf = (c, isG2) => (isG2 ? c.poolLimitG2 : c.poolLimitG1);
// 满员闸口的计数口径（2026-10-26 修复）：排除「已过期但还没被 pruneExpired 清掉」的号。
// 这些号到期后已不参与轮转，却仍然占着人数上限，导致满员提示比实际可登记名额早出现。
// 口径：exp 为空 / forever → 在册；形如 YYYY-MM-DD 且 < 今天 → 不计；其它异常格式按在册处理（保守）。
function activePoolSize(arr, today) {
  const t = today || beijingDate();
  let n = 0;
  for (const e of (arr || [])) {
    const x = String((e && e.exp) || '').trim();
    if (!x || x === 'forever') { n++; continue; }
    if (/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(x) && x < t) continue;
    n++;
  }
  return n;
}
async function ghPublicKey() {
  const g = await GH();
  const r = await fetch(`https://api.github.com/repos/${g.owner}/${g.repo}/actions/secrets/public-key`, { headers: { Authorization: `token ${g.token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'cron-relay-worker' } });
  return r.json();
}
// ---- blake2b (RFC 7693, BigInt 实现) ----
// GitHub Secrets API 要求 libsodium sealed box 格式：ephPub(32) || box(msg, nonce=blake2b24(ephPub||recipPub))
// 原实现缺临时公钥且 nonce 为零，是错的，任何密钥都写不进去。
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const BLAKE2B_SIGMA = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
];

function blake2b(input, outlen) {
  const MASK = (1n << 64n) - 1n;
  const rotr = (x, n) => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK;
  const G = (v, a, b, c, d, x, y) => {
    v[a] = (v[a] + v[b] + x) & MASK;
    v[d] = rotr(v[d] ^ v[a], 32);
    v[c] = (v[c] + v[d]) & MASK;
    v[b] = rotr(v[b] ^ v[c], 24);
    v[a] = (v[a] + v[b] + y) & MASK;
    v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = (v[c] + v[d]) & MASK;
    v[b] = rotr(v[b] ^ v[c], 63);
  };
  let h = BLAKE2B_IV.slice();
  h[0] ^= BigInt(outlen) | 0x01010000n;   // 无 key 的参数块
  const total = input.length;
  const nb = Math.max(1, Math.ceil(total / 128));
  const dv = new DataView(new ArrayBuffer(8));
  for (let i = 0; i < nb; i++) {
    const blk = new Uint8Array(128);
    blk.set(input.subarray(i * 128, (i + 1) * 128));
    const isLast = i === nb - 1;
    const t = BigInt(isLast ? total : (i + 1) * 128);
    // 消息字 m[0..15]，小端 64 位
    const m = [];
    for (let j = 0; j < 16; j++) {
      let w = 0n;
      for (let k = 7; k >= 0; k--) w = (w << 8n) | BigInt(blk[j * 8 + k]);
      m.push(w);
    }
    const v = new Array(16);
    for (let j = 0; j < 8; j++) v[j] = h[j];
    for (let j = 0; j < 8; j++) v[8 + j] = BLAKE2B_IV[j];
    v[12] ^= t;
    if (isLast) v[14] = ~v[14] & MASK;
    for (let r = 0; r < 12; r++) {
      const s = (r % 10) * 16;
      G(v, 0, 4, 8, 12, m[BLAKE2B_SIGMA[s]], m[BLAKE2B_SIGMA[s + 1]]);
      G(v, 1, 5, 9, 13, m[BLAKE2B_SIGMA[s + 2]], m[BLAKE2B_SIGMA[s + 3]]);
      G(v, 2, 6, 10, 14, m[BLAKE2B_SIGMA[s + 4]], m[BLAKE2B_SIGMA[s + 5]]);
      G(v, 3, 7, 11, 15, m[BLAKE2B_SIGMA[s + 6]], m[BLAKE2B_SIGMA[s + 7]]);
      G(v, 0, 5, 10, 15, m[BLAKE2B_SIGMA[s + 8]], m[BLAKE2B_SIGMA[s + 9]]);
      G(v, 1, 6, 11, 12, m[BLAKE2B_SIGMA[s + 10]], m[BLAKE2B_SIGMA[s + 11]]);
      G(v, 2, 7, 8, 13, m[BLAKE2B_SIGMA[s + 12]], m[BLAKE2B_SIGMA[s + 13]]);
      G(v, 3, 4, 9, 14, m[BLAKE2B_SIGMA[s + 14]], m[BLAKE2B_SIGMA[s + 15]]);
    }
    for (let j = 0; j < 8; j++) h[j] = (h[j] ^ v[j] ^ v[j + 8]) & MASK;
  }
  // 输出小端 64 位字，截断到 outlen
  const out = new Uint8Array(outlen);
  let o = 0;
  for (let j = 0; j < 8 && o < outlen; j++) {
    dv.setBigUint64(0, h[j], true);
    const tmp = new Uint8Array(dv.buffer);
    for (let k = 0; k < 8 && o < outlen; k++) out[o++] = tmp[k];
  }
  return out;
}

// ---- libsodium sealed box ----
function sealBox(msgU8, theirPub) {
  const eph = nacl.box.keyPair();
  const seed = new Uint8Array(64);
  seed.set(eph.publicKey, 0);
  seed.set(theirPub, 32);
  const nonce = blake2b(seed, 24);
  const boxed = nacl.box(msgU8, nonce, theirPub, eph.secretKey);
  const out = new Uint8Array(32 + boxed.length);
  out.set(eph.publicKey, 0);
  out.set(boxed, 32);
  return out;
}

async function ghPutSecret(name, value) {
  const g = await GH();
  const pk = await ghPublicKey();
  if (!pk || !pk.key || !pk.key_id) throw new Error('获取 GitHub Secrets 公钥失败（GH_TOKEN 无效/过期或仓库不对）：' + JSON.stringify(pk).slice(0, 120));
  const theirPub = b64dec(pk.key);
  const sealed = sealBox(utf8(value), theirPub);
  const r = await fetch(`https://api.github.com/repos/${g.owner}/${g.repo}/actions/secrets/${name}`, {
    method: 'PUT',
    headers: { Authorization: `token ${g.token}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': 'cron-relay-worker' },
    body: JSON.stringify({ encrypted_value: b64enc(sealed), key_id: pk.key_id }),
  });
  // 2026-10-22 加固：此前返回 status 但调用方不检查，422（值超 48KB）等失败被静默吞掉，
  // 导致最大分片连续 4 天写不进去没人发现。现在非 2xx 直接抛错让登记/resync 显式失败。
  // 2026-10-22 二次修复：Secret 写入成功时 GitHub 可能返回 201（新建）也可能是 204（更新）。
  // 只认 200/201 会把 204 判成失败 → pushPool 写完 NB_POOL_1 就抛错，后面 11 个槽位留着旧值，
  // 结果是号池被切成「新一片 + 旧十一 片」，比写不进去更危险。改为 2xx 一律算成功。
  if (!r.ok) {
    throw new Error(`写入 Secret ${name} 失败 HTTP ${r.status}（值过大或 GH_TOKEN 无权限）`);
  }
  return r.status;
}

// ---- 分片写回 NB_POOL_1..5 ----
// added 统一按北京时间记（2026-10-13 修复：此前用 UTC，北京 0-8 点登记的号会被提前一天入池，
// 与 run.py 的北京时间口径不一致）
function beijingDate() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
}
// ---- 有效期（exp）：'YYYY-MM-DD' 到期即移除；无 exp / 'forever' = 永久 ----
function isExpiredEntry(e) {
  return !!(e && e.exp && e.exp !== 'forever' && String(e.exp) < beijingDate());
}
function expDaysLeft(e) {
  if (!e || !e.exp || e.exp === 'forever') return Infinity;
  return Math.round((new Date(e.exp + 'T00:00:00Z') - new Date(beijingDate() + 'T00:00:00Z')) / 86400000);
}
function isSoonExpired(e) {
  const d = expDaysLeft(e);
  return d !== Infinity && d <= 3;
}
function beijingDatePlus(n) {
  return new Date(Date.now() + 8 * 3600 * 1000 + n * 86400 * 1000).toISOString().slice(0, 10);
}
function parseExpInput(x) {
  if (x == null || String(x).trim() === '') return { ok: true };
  const s = String(x).trim();
  if (s === 'forever' || s === '永久') return { ok: true, exp: 'forever' };
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return { ok: true, exp: s };
  if (/^\d{1,4}$/.test(s)) return { ok: true, exp: beijingDatePlus(parseInt(s, 10)) };
  return { ok: false };
}

// ====================================================================
// 客服标签 / 套餐档位（2026-10-27 新增）
// 背景：APK 与 EXE 都是客服用来登记的，人一多就分不清谁登记的；而「客服名字写死在软件里」
//       会导致每次人员变动都要重新打包 + 所有人重装。所以名单放在服务端，客户端每次登记前拉一份。
// 存放：D1 kv_misc 的 k='reg_cfg'（两群共用同一个 D1 库 → 只维护一份，两群自动一致）；
//       KV 同名键 REG_CFG 只作兜底镜像（D1 挂了才读）。
// 口径：accounts.agent 存客服名字原文，accounts.plan 存套餐「显示名」（1年/2年/永久），
//       统计按买的套餐算，不按剩余天数算（exp 可改可续，会漂）。
// ====================================================================
const REG_CFG_KEY = 'reg_cfg';
const REG_CFG_KV = 'REG_CFG';
const REG_CFG_DEFAULT = {
  agents: ['徐'],
  // 2026-10-27：加「1月」（30 天）档。档位顺序 = 客户端下拉顺序，从短到长排。
  plans: [
    { key: '1m', label: '1月', days: 30 },
    { key: '1y', label: '1年', days: 365 },
    { key: '2y', label: '2年', days: 730 },
    { key: 'forever', label: '永久', days: 0 },
  ],
};

// 客服名：去空白/控制字符/引号，最长 16 字。不校验是否在名单内 ——
// 名单随时会改，旧客户端可能还在提交已删掉的名字，直接拒绝会让登记全线失败。
function normAgent(x) {
  return String(x == null ? '' : x).replace(/[\u0000-\u001f\u007f"'<>]/g, '').trim().slice(0, 16);
}

function normRegCfg(o) {
  const out = { agents: [], plans: [] };
  const src = (o && typeof o === 'object') ? o : {};
  for (const a of (Array.isArray(src.agents) ? src.agents : [])) {
    const v = normAgent(a);
    if (v && !out.agents.includes(v)) out.agents.push(v);
  }
  for (const p of (Array.isArray(src.plans) ? src.plans : [])) {
    if (!p || typeof p !== 'object') continue;
    const label = String(p.label || '').trim().slice(0, 8);
    if (!label) continue;
    const days = Math.max(0, Math.min(36500, parseInt(p.days, 10) || 0));
    const key = String(p.key || label).trim().slice(0, 16) || label;
    if (out.plans.some(x => x.key === key)) continue;
    out.plans.push({ key: key, label: label, days: days });
  }
  if (!out.agents.length) out.agents = REG_CFG_DEFAULT.agents.slice();
  if (!out.plans.length) out.plans = REG_CFG_DEFAULT.plans.map(p => ({ key: p.key, label: p.label, days: p.days }));
  return out;
}

// 读配置：D1 → KV → 内置默认。任何异常都不抛，绝不阻塞登记。
async function regCfg() {
  let raw = null;
  if (d1ok()) {
    try {
      const rows = await d1All('SELECT v FROM kv_misc WHERE k=?', [REG_CFG_KEY]);
      if (rows && rows.length) raw = rows[0].v;
    } catch (e) { console.error('读 reg_cfg(D1) 失败:', e && e.message); }
  }
  if (!raw) {
    try { raw = await POOL.get(REG_CFG_KV); } catch (e) {}
  }
  let o = null;
  try { o = raw ? JSON.parse(raw) : null; } catch (e) { o = null; }
  return normRegCfg(o);
}

// 写配置：控制台「客服名单」用（只读口令进不来，见 /api/console/cfg）。D1 为主，KV 兜底镜像。
async function saveRegCfg(o) {
  const cfgN = normRegCfg(o);
  const s = JSON.stringify(cfgN);
  let d1 = false;
  if (d1ok()) {
    d1 = await d1Run('INSERT INTO kv_misc (k,v,updated_at) VALUES (?,?,?) ' +
      'ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at',
      [REG_CFG_KEY, s, new Date().toISOString()]);
  }
  try { await POOL.put(REG_CFG_KV, s); } catch (e) {}
  return { ok: !!d1, cfg: cfgN };
}

// 把客户端传来的「套餐」（key 或显示名都认）解析成 {key,label,exp}
function planOf(cfg, x) {
  const s = String(x == null ? '' : x).trim();
  if (!s) return null;
  const p = (cfg.plans || []).find(it => it.key === s || it.label === s);
  if (!p) return null;
  return { key: p.key, label: p.label, exp: (p.days > 0 ? beijingDatePlus(p.days) : 'forever') };
}
// 到期账号清理：删独立键 + 记墓碑 + 刷 master + 回推 GitHub Secrets（只在有过期时才写）
async function pruneExpired() {
  const master = await mergePool();
  const dead = master.filter(isExpiredEntry);
  if (!dead.length) return { master: master, count: 0 };
  // 读走 D1 后必须两边一起删：只删 KV 的话，下一次 mergePool 会从 D1 把过期号读回来。
  await Promise.all(dead.map(async e => {
    await POOL.delete(entryKeyOf(e));
    if (!(await d1Delete(e))) console.error('D1 过期删除失败:', e && (e.name || e.uid));
  }));
  try {
    const log = new Set(await getDeadLog());
    for (const e of dead) log.add(entryKeyOf(e));
    await POOL.put('dead_log', JSON.stringify([...log].slice(-500)));
  } catch (e) {}
  const kept = master.filter(e => !isExpiredEntry(e));
  await d1LogDead(dead, 'expired');
  // 2026-10-26：到期待清理同样是「静默删号」—— 而且更隐蔽：号池管理工具每打开一次列表
  // 就会顺手清一批，号主在毫不知情的情况下发现自己歌没人听了。同样进通知队列：
  // 12 小时内重新登记（= 续费）→ 判定回池，不发；没回来 → 发「账号信息过期，麻烦重新登记」。
  // 量通常个位数，逐条写；失败只记日志，不影响清理主流程。
  try { for (const e of dead) await d1QueueNotice(e); } catch (e) { console.error('通知队列写入失败:', e && e.message); }
  // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
  await pushPool(kept);
  try { await refreshPoolSnap(); } catch (e) {}   // 号池变了 → 刷新单键应急快照
  return { master: kept, count: dead.length };
}
async function gzipU8(u8) {
  // 2026-10-22：分片 JSON 先 gzip 再 base64。此前直接 base64 JSON，分片 45000 字符
  // 封装后约 1.78 倍膨胀到 ~80KB，超过 GitHub Secret 48KB 上限 → 最大那片恒被 422
  // 拒绝（且空槽都成功，表面看 resync 正常），老账号变更自 10-18 起没进过 Actions 号池。
  const cs = new CompressionStream('gzip');
  const stream = new Blob([u8]).stream().pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// 2026-10-22：Secrets 分片降级为「只读回退备份」，默认不再随每次登记/删除重写。
// 原因：一次 pushPool = 12 次 ghPutSecret（每次 X25519 + sealed box + 加密 + PUT），
// 是整个 worker 最大的 CPU 消耗；而所有读者（run.py / make_accounts.py / run.yml plan）
// 现在都先走 D1（/api/assign、/api/pool_stat），只有 D1 完全不可用时才回退 Secrets。
// 紧急需要重推一份全量快照：KV 里把 PUSH_SECRETS 设为 '1'，或直接调 /api/resync（强制推）。
let _pushOn = null, _pushOnAt = 0;
async function pushPoolEnabled() {
  if (_pushOn !== null && Date.now() - _pushOnAt < 60000) return _pushOn;
  try { _pushOn = (cleanKV(await POOL.get('PUSH_SECRETS')) === '1'); }
  catch (e) { _pushOn = false; }
  _pushOnAt = Date.now();
  return _pushOn;
}

async function pushPool(entries, force) {
  if (!force && !(await pushPoolEnabled())) return { skipped: true, count: entries.length };
  const CHUNK_MAX = 40000;  // 原始 JSON 字符数；实测 gzip≈0.52 字节/字符（CK hex 不可压缩），b64+sealed 后 ~37KB < 48KB
  const SLOT_N = 12;        // 槽位 NB_POOL_1..12（读取端 run.py / run.yml plan 已同步扩到 12）；12×4万字符 ≈ 550 号容量 > 500 上限
  const chunks = [];
  let cur = [];
  let size = 0;
  for (const e of entries) {
    const s = JSON.stringify(e).length + 1;
    if (size + s > CHUNK_MAX && cur.length) { chunks.push(cur); cur = []; size = 0; }
    cur.push(e); size += s;
  }
  if (cur.length) chunks.push(cur);
  if (chunks.length > SLOT_N) {
    const dropped = chunks.slice(SLOT_N).reduce((n, c) => n + c.length, 0);
    console.error(`号池 ${entries.length} 条超出 ${SLOT_N} 片 Secrets 容量，超出的 ${dropped} 条未写入，请扩容或清理！`);
  }
  for (let i = 0; i < SLOT_N; i++) {
    const name = `NB_POOL_${i + 1}`;
    if (i < chunks.length) await ghPutSecret(name, b64enc(await gzipU8(utf8(JSON.stringify(chunks[i])))));
    else await ghPutSecret(name, b64enc(await gzipU8(utf8('[]'))));
  }
}

// ---- 号池并发安全 ----
// 真实来源 = 每条账号一个独立 KV 键（entry: 前缀）。单键写入/删除互不干扰，从根上消除
// "整表读-改-写"竞态（此前多人同时登记会整表互相覆盖，表现为号池条目凭空减少）。
// master 键降级为合并视图缓存：即使被并发写坏，下次 mergePool 会从独立键自动重建。
function entryKeyOf(e) {
  return e && e.uid != null && String(e.uid) !== ''
    ? 'entry:u' + String(e.uid)
    : 'entry:n' + encodeURIComponent(String((e && e.name) || 'unknown'));
}

// 删除墓碑：report_dead/管理删除过的账号键记录在 dead_log，防止
// ① master 边缘缓存旧快照（≤60s）把已删条目"复活"回填；
// ② 刚被清理的成员在缓存窗口内重新登记被误判"已登记"。重新登记成功后自动移除墓碑。
async function getDeadLog() {
  try { return JSON.parse(await POOL.get('dead_log') || '[]') || []; } catch (e) { return []; }
}

async function mergePool() {
  // 读走 D1：一条 SELECT 取代原来的「1 次 list + N 次 POOL.get」。
  // 号池 213 个号时，这一步从 214 次 KV 读 / 214KB 传输降到 1 次 D1 查询。
  const d1 = await d1Pool();
  if (d1) return d1;
  return await mergePoolKV();
}

// 纯 KV 版合并（不做 D1 优先）。
// 用途：/api/d1_sync 必须拿「KV 的真实内容」去对齐 D1，走 mergePool 会变成 D1 对齐 D1，没有意义。
async function mergePoolKV() {
  // ① 单键快照优先（2026-10-22 第三批）：1 次 KV 读拿到全池。
  //    原来的「list + 逐键 get」在 1200 个号时是 1201 次外部操作，超过单次 invocation 的
  //    1000 次外部操作上限 → 兜底路径必然失败，灾备形同虚设。
  try {
    const snap = await POOL.get(poolSnapKey());
    if (snap) {
      const arr = JSON.parse(snap);
      if (Array.isArray(arr) && arr.length) {
        const dead = new Set(await getDeadLog());
        return arr.filter(e => !dead.has(entryKeyOf(e)));
      }
    }
  } catch (e) { console.error('号池快照读取失败，回退 entry 键:', e && e.message); }

  // ② 没有快照 → 退回 entry: 独立键（真实来源），但必须限制读取条数：
  //    1 次 dead_log + 1~2 次 list + 最多 900 次 get < 1000（单次 invocation 外部操作上限）。
  const MAX_KEYS = 900;
  const keyNames = [];
  let cursor, truncated = false;
  do {
    const page = await POOL.list({ prefix: 'entry:', limit: 1000, cursor });
    for (const k of page.keys) {
      if (keyNames.length >= MAX_KEYS) { truncated = true; break; }
      keyNames.push(k.name);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && !truncated);
  if (truncated) console.error('KV 兜底：entry 键超过 ' + MAX_KEYS + ' 个，已截断（单次调用 1000 次外部操作上限）');
  // 2026-10-22：master 是 ~200KB 的旧合并缓存，以前每次都先读它再合并，等于每次回退都白传一次
  // 大对象 + 解析。只在「一个 entry: 键都读不到」的极端情况（首次迁移 / 键被误删）才读它兜底。
  let base = [];
  if (!keyNames.length) {
    try { base = JSON.parse(await POOL.get('master') || '[]') || []; } catch (e) {}
  }
  const deadLog = new Set(await getDeadLog());
  const byKey = new Map();
  for (const e of base) {
    if (deadLog.has(entryKeyOf(e))) continue;   // 墓碑内的缓存残留不参与（已删账号不复活）
    byKey.set(entryKeyOf(e), e);                // 顺带去重历史重复条目
  }
  const vals = await Promise.all(keyNames.map(n => POOL.get(n)));
  let changed = false;
  for (let i = 0; i < keyNames.length; i++) {
    if (!vals[i]) { changed = true; continue; }        // 键已删但 list 索引未收敛，跳过
    let v; try { v = JSON.parse(vals[i]); } catch (e) { continue; }
    if (!byKey.has(keyNames[i])) { byKey.set(keyNames[i], v); changed = true; }
  }
  const merged = [...byKey.values()];
  // 回填：master 有但独立键缺失的老数据（首次升级时一次性迁移，之后不再触发）
  const listed = new Set(keyNames);
  await Promise.all(merged
    .filter(e => !listed.has(entryKeyOf(e)))
    .map(e => POOL.put(entryKeyOf(e), JSON.stringify(e))));
  if (changed || merged.length !== base.length) {
    // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
  }
  return merged;
}

// 读全池，并保证包含「刚写入的那一条」。
// 用途：登记成功后要推 Secrets 分片，如果 D1 镜像写失败或读延迟，这个新号就会从分片里消失，
// 第二天签到/发动态就漏号。这里按主键再兜一次，成本只是一次字符串比较。
async function mergePoolEntry(entry, ekey) {
  const list = await mergePool();
  const k = ekey || entryKeyOf(entry);
  if (!list.some(e => entryKeyOf(e) === k)) list.push(entry);
  return list;
}

async function addEntry(entry) {
  // 有效期默认 2 年（730 天），管理端可随时修改（exp=YYYY-MM-DD，forever=永久）
  if (!entry.exp) entry.exp = beijingDatePlus(730);
  const ekey = entryKeyOf(entry);
  const uidKey = entry.uid != null ? String(entry.uid) : null;

  // ---- D1 快速路径：一次 SELECT 完成查重（原路径要把 213 个 entry 键全读一遍）----
  if (d1ok()) {
    // uid 为空的（用 name 占位的老号）只能按 name 查。不带 uid 时不要拼那个 ? 占位符，
    // 否则得传哨兵值，而 D1 绑定含 NUL 的字符串会报错 → 白走一次 KV 回退。
    const dup = uidKey
      ? await d1All('SELECT uid FROM accounts WHERE pool=? AND (uid=? OR name=?) LIMIT 1',
                    [POOL_NAME, uidKey, String(entry.name || '')])
      : await d1All('SELECT uid FROM accounts WHERE pool=? AND name=? LIMIT 1',
                    [POOL_NAME, String(entry.name || '')]);
    if (dup === null) {
      console.error('D1 查重失败，回退 KV 全量查重');
    } else {
      if (dup.length) {
        return { ok: false, msg: '该账号已登记过（每个账号限登记一首歌），无需重复登记。' };
      }
      // KV 仍写一份：D1 万一回滚，KV 里必须是完整数据
      await POOL.put(ekey, JSON.stringify(entry));
      if (!(await d1Upsert(entry))) {
        console.error('D1 登记镜像失败（KV 已写入，可用 /api/resync 补齐）');
      }
      // 重新登记 → 清墓碑（只影响 KV 回退路径）
      try {
        const deadLog = new Set(await getDeadLog());
        if (deadLog.size) {
          const cleared = [...deadLog].filter(k => k !== ekey
            && !(uidKey && k === 'entry:u' + uidKey)
            && !(entry.name && k === 'entry:n' + encodeURIComponent(String(entry.name))));
          if (cleared.length !== deadLog.size) await POOL.put('dead_log', JSON.stringify(cleared));
        }
      } catch (e) {}
      // 只有真要推 Secrets 时才做「全池 + 新号」合并（那是一次全表读）——
      // 默认关闭推送后，这里不该再为一份没人读的分片白跑一次查询。
      if (await pushPoolEnabled()) await pushPool(await mergePoolEntry(entry, ekey));
      try { await refreshPoolSnap(); } catch (e) {}
      return { ok: true };
    }
  }

  // ---- KV 回退路径（D1 未绑定或查询失败）----
  if (await POOL.get(ekey)) {
    return { ok: false, msg: '该账号已登记过（每个账号限登记一首歌），无需重复登记。' };
  }
  const deadLog = new Set(await getDeadLog());
  const master = await mergePool();
  for (const e of master) {
    if (deadLog.has(entryKeyOf(e))) continue;   // 墓碑内的是缓存残留（刚被清理），不算已登记
    if (uidKey && e.uid != null && String(e.uid) === uidKey) {
      return { ok: false, msg: '该账号已登记过（每个账号限登记一首歌），无需重复登记。' };
    }
    if (entry.name && e.name === entry.name) {
      return { ok: false, msg: '该手机号/账号已登记过（每个账号限登记一首歌），无需重复登记。' };
    }
  }
  // 权威写入：只写自己的独立键，永远不会覆盖别人的登记
  await POOL.put(ekey, JSON.stringify(entry));
  // D1 影子库同步（2026-10-22）：失败只记日志，绝不影响登记结果
  try { await d1Upsert(entry); } catch (e) { console.error('D1 镜像失败:', e && e.message); }
  // 重新登记成功 → 清掉墓碑（dead_log 里移除本账号的 uid 键与 name 键两种形态）
  if (deadLog.size) {
    const cleared = [...deadLog].filter(k => k !== ekey
      && !(uidKey && k === 'entry:u' + uidKey)
      && !(entry.name && k === 'entry:n' + encodeURIComponent(String(entry.name))));
    if (cleared.length !== deadLog.size) {
      try { await POOL.put('dead_log', JSON.stringify(cleared)); } catch (e) {}
    }
  }
  // master 缓存尽力刷新（此写有竞态也无害：下次 mergePool 自愈）
  const updated = master.concat([entry]);
  // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
  await pushPool(updated);
  // 本分支是「D1 查重失败」才走到：如果只是查询超时（D1 仍可写），这次快照能补上新号；
  // 真的未绑定时 refreshPoolSnap 自己会因 d1ok() 为假直接返回 false，不会抛错。
  try { await refreshPoolSnap(); } catch (e) {}
  return { ok: true };
}

// ====================================================================
// D1 号池（2026-10-22 新增；KV 仍是唯一权威，D1 是影子库，双写 + 只读查询）
// 目的：
//   ① 让 run.py 直接问「我这一班该跑哪些号、每个号听哪几首」，彻底废掉
//      GitHub Secrets 分片（48KB 上限 / 槽位上限 500 / 半更新 三个问题一起消失）；
//   ② 每日轮转分配：听众集合每天 100% 更换，但每首歌每天恰好 p 个听众，一个都不漏。
// 约定：任何 D1 异常只 console.error，绝不抛出、绝不影响 KV 主流程。
// ====================================================================
const POOL_NAME = 'hz';        // 主群；dingzhi 版为 'dz'
const ASSIGN_TARGET = 30;      // 每首歌每天的目标听众数
// 跨群互听/控制台拉对端的默认地址（KV 里 PEER_URL 可覆盖）。
// 2026-10-23：dz.xx1031.xyz 已下线（该域名随旧邮件流到用户手里），定制版统一用 dingzhi.xx1031.xyz。
const PEER_DEFAULT = 'https://dingzhi.xx1031.xyz';

function d1ok() {
  try { return typeof DB !== 'undefined' && DB && typeof DB.prepare === 'function'; } catch (e) { return false; }
}
// ====================================================================
// 2026-10-25：歌曲/账号元数据自动补齐（控制台打开时后台补几条，慢慢补完）
// 用途：song_meta / acc_meta 是控制台「共创歌曲 / 绑错歌」标签的数据源，
//       新号登记后如果没人跑 tmp/sync_song_meta.py，这两张表就会缺数据（缺了只是不打标签，不会报错）。
// 策略：每次控制台加载顺手补 6 首歌 + 4 个号，全部 try/catch 静默失败，绝不阻塞、绝不影响页面。
async function backfillMeta(){
  if(!d1ok())return {skip:1};
  const now=new Date(Date.now()+8*3600*1000).toISOString().replace('T',' ').slice(0,19);
  // 这两个接口用桌面 Chrome UA 更稳（全局 UA 是 iPhone 版，登录接口在用，别动它）
  const MUA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));
  const stat={songs:0,acc:0,empty:0,fail:0,err:'',at:now};
  // ① 没同步过的歌：批量调网易歌曲详情，拿作者列表（一次 12 首，1 个 subrequest 解决）
  try{
    const rows=await d1All("SELECT DISTINCT a.song AS song FROM accounts a WHERE a.song IS NOT NULL AND a.song<>'' AND NOT EXISTS (SELECT 1 FROM song_meta m WHERE m.song=a.song) LIMIT 12");
    const ids=(rows||[]).map(r=>String(r.song));
    if(ids.length){
      const r=await fetch(BASE+'/api/song/detail?ids=%5B'+ids.join(',')+'%5D',{headers:{'User-Agent':MUA,Referer:BASE+'/'}});
      const j=await r.json();
      const got=(j&&Array.isArray(j.songs))?j.songs:[];
      const st=[];
      for(const s of got){
        const arts=(s.artists||s.ar||[]).map(x=>[String(x.id),x.name||'']);
        st.push(DB.prepare('INSERT OR REPLACE INTO song_meta(song,name,dur,n_artists,artists,first_artist,gone,updated_at) VALUES (?,?,?,?,?,?,0,?)')
          .bind(String(s.id),s.name||'',Math.round((s.duration||s.dt||0)/1000),arts.length,JSON.stringify(arts),arts[0]?arts[0][1]:'',now));
        stat.songs++;
      }
      // 网易没返回的 = 已下架/删除，标 gone
      for(const id of ids){
        if(!got.some(s=>String(s.id)===id))
          st.push(DB.prepare('INSERT OR REPLACE INTO song_meta(song,name,dur,n_artists,artists,first_artist,gone,updated_at) VALUES (?,?,?,?,?,?,1,?)')
            .bind(id,'',0,0,'[]','',now));
      }
      if(st.length)await DB.batch(st);
    }
  }catch(e){ stat.err='song:'+((e&&e.message)||e); }
  // ② 没同步过音乐人身份的号：逐个查公开 user/detail（无需 CK）。
  //    注意两点：① acc_meta 里「上次失败」的 NULL 占位行也要算待补（NOT EXISTS 会漏，踩过）；
  //             ② 连发太快会被网易按「操作频繁 code=405」限流，每个请求之间必须留间隔。
  try{
    const rows=await d1All("SELECT DISTINCT a.uid AS uid FROM accounts a LEFT JOIN acc_meta m ON m.uid=a.uid WHERE a.song IS NOT NULL AND a.song<>'' AND (m.uid IS NULL OR m.artist_id IS NULL) LIMIT 20");
    for(const row of (rows||[])){
      const uid=String(row.uid);
      await sleep(260);
      try{
        const r=await fetch(BASE+'/api/v1/user/detail/'+uid,{headers:{'User-Agent':MUA,Referer:BASE+'/'}});
        const j=await r.json();
        const p=(j&&j.profile)||null;
        if(!p){ stat.fail++; if(j&&j.code)stat.err='acc:'+j.code; continue; }
        await DB.prepare('INSERT OR REPLACE INTO acc_meta(uid,artist_id,artist_name,updated_at) VALUES (?,?,?,?)')
          .bind(uid,String(p.artistId||''),p.artistName||'',now).run();
        if(p.artistId)stat.acc++; else stat.empty++;
      }catch(e){ stat.fail++; stat.err='acc:'+((e&&e.message)||e); }
    }
  }catch(e){ stat.err='accouter:'+((e&&e.message)||e); }
  // 记一行执行结果，方便排查（D1 kv_misc 的 meta:last）
  try{ await DB.prepare('INSERT OR REPLACE INTO kv_misc(k,v,updated_at) VALUES (?,?,?)').bind('meta:last',JSON.stringify(stat),now).run(); }catch(e){}
  return stat;
}
async function d1All(sql, params) {
  if (!d1ok()) return null;
  try {
    const st = DB.prepare(sql);
    const r = params && params.length ? await st.bind(...params).all() : await st.all();
    return (r && r.results) || [];
  } catch (e) { console.error('D1 all 失败:', e && e.message); return null; }
}

// 死号流水写 D1（2026-10-22 新增）：KV 里的 dead_log 只是「墓碑名单」，最多 500 条、只存键名，
// 看不出是谁、什么时候、因为什么被清理。D1 dead_log 表存完整流水，供周报统计与事后追查。
async function d1LogDead(entries, reason) {
  if (!d1ok() || !entries || !entries.length) return;
  const at = new Date(Date.now() + 8 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);
  for (const e of entries) {
    try {
      await d1Run('INSERT INTO dead_log (pool,uid,name,reason,at) VALUES (?,?,?,?,?)',
        [POOL_NAME,
         e && e.uid != null && String(e.uid) !== '' ? String(e.uid) : null,
         e && e.name ? String(e.name) : null,
         reason || 'unknown', at]);
    } catch (err) { console.error('D1 死号流水写入失败:', err && err.message); }
  }
}

// 北京时间时间戳（YYYY-MM-DD HH:MM:SS），dead_log / dead_notice 统一口径，字符串可比大小
function bjStamp(ms) {
  return new Date((ms != null ? ms : Date.now()) + 8 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);
}

// 手动删号的「是否通知号主」队列（2026-10-26 新增）。
// 背景：控制台删号在 worker 内部完成（applyEntryEdit），全程没有任何 Python 进程参与，
//       而 SMTP 只能从 GitHub Actions 侧发 → 之前 12 条手动删除一封邮件都没发出去。
// 口径：不无脑发，只对「真删」发（判定逻辑见 /api/dead_pending）。
// 没留邮箱的号也入队（判定时标 skip_noemail）—— 这样控制台每条手动删号都有明确状态，
// 不会出现「删了但不知道通没通知」的空白行。
async function d1QueueNotice(e) {
  if (!d1ok() || !e) return false;
  return d1Run('INSERT OR IGNORE INTO dead_notice (pool,uid,name,email,removed_at,state) VALUES (?,?,?,?,?,?)',
    [POOL_NAME, String(e.uid != null ? e.uid : ''), String(e.name || ''), String(e.email || '').trim(), bjStamp(), 'pending']);
}

async function d1Run(sql, params) {
  if (!d1ok()) return false;
  try {
    const st = DB.prepare(sql);
    if (params && params.length) await st.bind(...params).run(); else await st.run();
    return true;
  } catch (e) { console.error('D1 run 失败:', e && e.message); return false; }
}
// 单条镜像（新增/修改后调用）。
// 2026-10-26 修复：无 uid 的历史条目以前直接 return false，导致这些号在控制台上的
// 「改歌 / 改邮箱 / 改有效期」只写进 KV，而读路径走 D1 → 刷新一次就变回旧值（假成功）。
// D1 里这类行的定位键是 'name:<name>' 占位（见 d1RowToEntry 的反向还原），这里按同一口径写。
async function d1Upsert(e) {
  if (!d1ok() || !e) return false;
  let uid = e.uid != null ? String(e.uid) : '';
  if (!uid) {
    if (!e.name) return false;
    uid = 'name:' + String(e.name);
  }
  return d1Run(
    'INSERT INTO accounts (pool,uid,name,song,ck,added,exp,no_listen,email,updated_at,agent,plan) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ' +
    'ON CONFLICT(pool,uid) DO UPDATE SET name=excluded.name, song=excluded.song, ck=excluded.ck, ' +
    'added=excluded.added, exp=excluded.exp, no_listen=excluded.no_listen, email=excluded.email, ' +
    'updated_at=excluded.updated_at, ' +
    // 2026-10-27：agent/plan 用「新值非空才覆盖」——/api/d1_sync 之类从 KV 老数据回灌时，
    // KV 里没有这两列，无脑覆盖会把 505 个存量号的客服归属一次清空。
    'agent=CASE WHEN excluded.agent<>\'\' THEN excluded.agent ELSE accounts.agent END, ' +
    'plan=CASE WHEN excluded.plan<>\'\' THEN excluded.plan ELSE accounts.plan END',
    [POOL_NAME, uid, String(e.name || ''), String(e.song || ''), String(e.ck || ''), String(e.added || ''),
     String(e.exp || ''), e.noListen ? 1 : 0, String(e.email || ''), new Date().toISOString(),
     String(e.agent || ''), String(e.plan || '')]
  );
}
async function d1Delete(e) {
  if (!d1ok() || !e) return false;
  const uid = e.uid != null ? String(e.uid) : '';
  if (uid) return d1Run('DELETE FROM accounts WHERE pool=? AND uid=?', [POOL_NAME, uid]);
  if (e.name) return d1Run('DELETE FROM accounts WHERE pool=? AND name=?', [POOL_NAME, String(e.name)]);
  return false;
}

// ====================================================================
// D1 读路径（2026-10-22 第二批：读也切到 D1）
// 背景：KV 的 mergePool 要 list 一次 + 把每个 entry 键读一遍（213 次读），
// 这是「日读 3.6 万」和「p50 CPU 9ms」的主要来源。D1 一条 SELECT 就够。
// 设计原则：D1 只做读，写仍然「KV 权威 + D1 镜像」不变；D1 任何异常都回退 KV，
// 所以即使 D1 挂了，登记/控制台/分配也不会停，只是慢回旧路。
// ====================================================================
const D1_COLS = 'uid,name,song,ck,added,exp,no_listen,email,agent,plan';

// D1 行 → KV entry 结构（保持字段名完全一致，上层代码无需改动）
function d1RowToEntry(r) {
  const uidRaw = String(r.uid || '');
  // 无 uid 的历史条目在库里用 'name:xxx' 占位（导入时补的），这里还原成「无 uid」
  const e = {
    name: String(r.name || ''),
    song: String(r.song || ''),
    ck: String(r.ck || ''),
    added: String(r.added || ''),
    exp: String(r.exp || ''),
    email: String(r.email || ''),
    // 2026-10-27：客服标签 + 套餐档位。存量行 ALTER 时清一色刷成「徐」/空（空=未标注）。
    agent: String(r.agent || ''),
    plan: String(r.plan || ''),
  };
  if (uidRaw && !uidRaw.startsWith('name:')) e.uid = r.uid;
  if (r.no_listen) e.noListen = 1;
  return e;
}

// 返回 null = D1 不可用/查询失败/表为空（调用方回退 KV）；返回数组 = 正常
async function d1Pool() {
  if (!d1ok()) return null;
  const rows = await d1All('SELECT ' + D1_COLS + ' FROM accounts WHERE pool=? ORDER BY added, uid', [POOL_NAME]);
  if (!rows) return null;
  if (!rows.length) {
    // 空表几乎不可能（号池最少几十个号），当作异常处理，避免把「库被清空」误当成「号池为空」
    console.error('D1 号池为空，回退 KV 读取');
    return null;
  }
  return rows.map(d1RowToEntry);
}

// 快照写入：一次 batch 写完整片（原来是 POOL.put 一个 snap: 键）。
// 好处：控制台回看可以直接 SELECT，不用先 list 再逐个 get；也不再占用 KV 的 list 配额。
async function d1SnapWrite(day, pool, clean) {
  if (!d1ok()) return false;
  const uids = Object.keys(clean || {});
  if (!uids.length) return true;
  try {
    const now = new Date().toISOString();
    // 2026-10-24 修复：D1 单次 batch 最多 1000 条语句，而 snap650 是 jobs=1 写全池。
    // hz 登记上限 1200，号池涨到千级后会整批写入失败（快照一条都进不去）。
    // 与 d1DursWrite/d1RunsWrite 统一按 100 条分批；小批量仍只跑一次循环，行为不变。
    for (let i = 0; i < uids.length; i += 100) {
      const stmts = uids.slice(i, i + 100).map(uid => DB.prepare(
        'INSERT INTO snapshots (day,pool,uid,rate,rpc30,cnt,missions,dur,at) VALUES (?,?,?,?,?,?,?,?,?) ' +
        // 2026-10-23：dur 用 COALESCE —— 时长老早就由 run.py 在播放时写入，而 10:00 的补采任务
        // 只关心 650 指标、手里没有时长，直接覆盖会把「时长」列清空。rate/rpc30/missions
        // 必须原样覆盖（那正是补采的目的：用结算后的值替换凌晨的旧值）。
        'ON CONFLICT(day,pool,uid) DO UPDATE SET rate=excluded.rate, rpc30=excluded.rpc30, ' +
        'cnt=COALESCE(excluded.cnt, snapshots.cnt), missions=excluded.missions, ' +
        'dur=COALESCE(excluded.dur, snapshots.dur), at=excluded.at'
      ).bind(day, pool, String(uid), clean[uid].rate, clean[uid].rpc30, clean[uid].cnt,
             JSON.stringify(clean[uid].mis || {}), clean[uid].dur, now));
      await DB.batch(stmts);
    }
    return true;
  } catch (e) { console.error('D1 快照写入失败:', e && e.message); return false; }
}

// 时长沉淀（2026-10-22 新增 D1 主存储）：原来只有一个 KV 键 console:durs，
// 250 个分片并发做「读→改→写」，必然互相覆盖（丢更新）。D1 按 (pool,uid) UPSERT 天然无竞态。
async function d1DursWrite(pool, incoming) {
  if (!d1ok()) return 0;
  const uids = Object.keys(incoming || {});
  if (!uids.length) return 0;
  try {
    const now = new Date().toISOString();
    for (let i = 0; i < uids.length; i += 100) {
      const batch = uids.slice(i, i + 100).map(uid => DB.prepare(
        'INSERT INTO durs (pool,uid,dur,updated_at) VALUES (?,?,?,?) ' +
        'ON CONFLICT(pool,uid) DO UPDATE SET dur=excluded.dur, updated_at=excluded.updated_at'
      ).bind(pool, String(uid), Number(incoming[uid]) || 0, now));
      await DB.batch(batch);
    }
    return uids.length;
  } catch (e) { console.error('D1 时长写入失败:', e && e.message); return 0; }
}

// 实跑名单（2026-10-22 新增）：记录「这一天这一片真正跑完播放的号」，
// 供 /api/coverage 核对「应跑 vs 实跑」，补上以前「整片静默丢失但 job 仍然绿」的盲区。
async function d1RunsWrite(day, pool, uids, slice) {
  if (!d1ok()) return 0;
  if (!uids || !uids.length) return 0;
  try {
    const now = new Date().toISOString();
    for (let i = 0; i < uids.length; i += 100) {
      const batch = uids.slice(i, i + 100).map(uid => DB.prepare(
        'INSERT INTO runs (day,pool,uid,slice,at) VALUES (?,?,?,?,?) ' +
        'ON CONFLICT(day,pool,uid) DO UPDATE SET slice=excluded.slice, at=excluded.at'
      ).bind(day, pool, String(uid), String(slice || ''), now));
      await DB.batch(batch);
    }
    return uids.length;
  } catch (e) { console.error('D1 实跑名单写入失败:', e && e.message); return 0; }
}

// 计数型限流（2026-10-22 第三批）：D1 原子自增，返回自增后的计数。
// 为什么不用 KV：KV 是「读一次、加一、写回」，两个并发请求会读到同一个旧值 → 各写回 n+1，
// 等于少算一次，频控直接被绕过；而且 KV 免费额度写只有 1000 次/天。
// 语义：先自增再判断，超限的请求也计一次（宁可多算，不漏）。
// 返回 null = D1 不可用／写入失败，调用方必须回退 KV，不能让频控失效。
async function d1Hit(kind, key) {
  if (!d1ok()) return null;
  const k2 = kind + ':' + key;
  const ok = await d1Run(
    'INSERT INTO rate_limit (k,n,at) VALUES (?,1,?) ON CONFLICT(k) DO UPDATE SET n=n+1, at=excluded.at',
    [k2, new Date().toISOString()]);
  if (!ok) return null;
  const rows = await d1All('SELECT n FROM rate_limit WHERE k=?', [k2]);
  if (!rows || !rows.length) return null;
  return Number(rows[0].n) || 0;
}

// ---- 单键号池快照（2026-10-22 第三批）----
// 背景：mergePoolKV 原来是「list 一次 + 每个 entry 键 get 一次」。1200 个号 = 1201 次外部操作，
// 而单个 invocation 最多只能做 1000 次外部操作（Cloudflare 硬限）→ D1 一挂，KV 兜底路径
// 自己也必然失败，等于「灾备是假的」。
// 做法：维护一个 pool:<池> 单键（全池 JSON），兜底时 1 次读就拿到全池。
// 它不承担权威职责（entry: 键才是），只是为了「D1 不可用时这一轮还能跑起来」，偶尔落后无妨。
const poolSnapKey = () => 'pool:' + POOL_NAME;

async function refreshPoolSnap() {
  if (!d1ok()) return false;
  const rows = await d1All('SELECT ' + D1_COLS + ' FROM accounts WHERE pool=? ORDER BY added, uid', [POOL_NAME]);
  if (!rows || !rows.length) return false;
  try {
    await POOL.put(poolSnapKey(), JSON.stringify(rows.map(d1RowToEntry)));
    return true;
  } catch (e) { console.error('号池快照写入失败:', e && e.message); return false; }
}

// ---- 每日轮转分配 ----
function dayIndexBJ() {
  const t = new Date(Date.now() + 8 * 3600 * 1000);
  return Math.floor(Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), t.getUTCDate()) / 86400000);
}
function hashStr(s) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h >>> 0;
}
// ---- 登记页访问口令（2026-10-23）----
// 背景：旧邮件正文里带过登记页地址，邮件被转发或页面被搜索收录后，任何人都能打开登记页。
// 需求：互助版网页加口令 music88888，但**软件（APK/EXE）不受影响** —— 它们调的是 /api/*，
// 所以闸门只挂在 GET / 与 /index.html 上，任何 /api/* 都不碰。
// 口令存在 KV 的 PAGE_PASS 键：值为空 = 不启用（改回空字符串即可随时关掉，不用改代码）。
// cookie 里存的是 hashStr('pg:'+口令)，不落明文。
const GATE_COOKIE = 'pgate';
// 2026-10-25：口令闸门仍是白名单式，只列要拦的网页路由，/api/* 一律放行（APK/EXE 不受影响）。
// ⚠️ **不要**把 /console、/admin 加进来：
//   ① 这两页各有自己的强口令（/console 认 KV CONSOLE_PASS 24 位、/admin 认 ADMIN_PASS 16 位），
//      而 PAGE_PASS 是 music88888、发给过全体 263 个成员 —— 用它当第二道锁等于没锁；
//   ② 闸门会 302 跳转，URL 里的 #pw= 免密 hash 在跳转时必丢，CK助手点「进阶控制台」
//      就变成「先输访问口令、再输控制台口令」两遍（2026-10-25 实测复现）。
const PAGE_ROUTES = new Set(['/', '/index.html']);
function gateCookieValue(pass) { return String(hashStr('pg:' + pass)); }
async function pageGate(request, url) {
  let pass = '';
  try { pass = cleanKV(await POOL.get('PAGE_PASS')); } catch (e) {}
  if (!pass) return null;                                  // 未配置口令 → 直接放行
  const want = gateCookieValue(pass);
  if (url.searchParams.get('k') === pass) {                 // 带对口令 → 种 cookie，去掉 query 后回原页面
    return new Response(null, { status: 302, headers: {
      'Location': url.pathname || '/',
      'Set-Cookie': `${GATE_COOKIE}=${want}; Max-Age=31536000; Path=/; HttpOnly; SameSite=Lax`,
    } });
  }
  const ck = request.headers.get('Cookie') || '';
  const m = ck.match(new RegExp('(?:^|;\\s*)' + GATE_COOKIE + '=([^;]+)'));
  if (m && m[1] === want) return null;                      // cookie 已通过 → 放行
  return new Response(GATE_HTML, {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
function seededShuffle(a, seed) {
  let s = (seed >>> 0) || 1;
  for (let i = a.length - 1; i > 0; i--) {
    s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
    const j = s % (i + 1); const t = a[i]; a[i] = a[j]; a[j] = t;
  }
  return a;
}
// 把「一行号池数据」规整成计划用的结构：D1 行（snake）与 KV entry（camel）都能喂进来。
function planRow(r) {
  if (!r) return null;
  const noListen = r.no_listen ? 1 : (r.noListen ? 1 : 0);
  // 是否有 CK：D1 主路径只回 0/1 的 hasck（省传输），KV 兜底路径行里直接有 ck。
  // 没有 CK 的行播不了，绝不能占听众名额 —— 否则那首歌每天白少一个听众，且谁也发现不了。
  const hasCk = (r.hasck !== undefined && r.hasck !== null)
    ? (Number(r.hasck) === 1)
    : (typeof r.ck === 'string' ? !!r.ck.trim() : true);
  return {
    pool: String(r.pool || POOL_NAME),
    uid: r.uid != null ? String(r.uid) : '',
    name: String(r.name || ''),
    song: String(r.song || ''),
    ck: String(r.ck || ''),
    email: String(r.email || ''),
    hasCk: hasCk,
    no_listen: noListen,
    added: String(r.added || ''),
    exp: String(r.exp || ''),
  };
}

// 纯计算（无 I/O）：D1 主路径与 KV 兜底共用同一套轮转逻辑，保证两条路算出的窗口完全一致。
function buildPlanFrom(rows, today) {
  const live = rows.filter(r => {
    const added = String(r.added || '');
    if (added && added >= today) return false;               // 当天新登记的次日才跑
    const exp = String(r.exp || '');
    if (exp && exp !== 'forever' && exp < today) return false;
    return true;
  });
  const songs = [...new Set(live.map(r => String(r.song || '')).filter(Boolean))].sort();
  const seen = new Set();
  const listeners = [];
  const idle = [];                                           // 只收不听：不进播放环，但要下发去签到/查工作台/验活
  for (const r of live) {
    const uid = String(r.uid || '');
    const key = String(r.pool) + ':' + uid;
    if (!uid || seen.has(key)) continue;
    if (!r.hasCk) continue;                                  // 空 CK 占位行不占听众名额
    seen.add(key);
    const item = { pool: String(r.pool), uid, name: r.name || '', song: r.song || '',
                   ck: r.ck, email: r.email || '' };
    if (r.no_listen) { idle.push(item); continue; }
    listeners.push(item);
  }
  const M = listeners.length, L = songs.length;
  if (!M || !L) return { ok: false, msg: '可用号或歌曲为空', m: M, l: L, idle, plans: [] };
  // p：先按「每首歌每天 ASSIGN_TARGET+1 个听众」反推，再夹进 [1, L-1]。
  // 2026-10-22 修正：原写法 Math.max(8, Math.min(L-1, x)) 在 L<9 时 p>L-1，每人取不满 p 首。
  const p = Math.max(1, Math.min(Math.max(8, Math.ceil((ASSIGN_TARGET + 1) * L / M)), Math.max(1, L - 1)));
  const day = Math.floor(Date.parse(today + 'T00:00:00Z') / 86400000);
  const off = ((day * p) % L + L) % L;
  const plans = [];
  for (let i = 0; i < M; i++) {
    const it = listeners[i];
    const base = Math.floor(i * L / M);
    const own = it.song;
    const picks = [];
    for (let j = 0; picks.length < p && j < L; j++) {
      const sid = songs[(base + off + j) % L];
      if (sid === own) continue;                             // 绝不听自己
      picks.push(sid);
    }
    seededShuffle(picks, hashStr(it.uid + ':' + day));
    plans.push({ pool: it.pool, uid: it.uid, name: it.name, song: own,
                 ck: it.ck, email: it.email, plays: picks });
  }
  return { ok: true, day: today, m: M, l: L, p, plans, idle };
}

// 返回全量 listeners 的播放计划；调用方按 i % jobs 取自己那一批。
// 覆盖性证明：第 i 个号的窗口起点 base=floor(i*L/M)，长度 p ⇒ 任一歌曲位置被
// 恰好 p*M/L（向上取整后 ≥p）个窗口覆盖 ⇒ 每首歌每天都有听众，且方差极小。
// 每日轮转：offset 每天 +p（=窗口长度）⇒ 相邻两天窗口完全不重叠 ⇒ 听众集合全换。
async function buildPlan(dayStr) {
  // dayStr：整轮任务统一的「日期锚点」（由 run.yml 的 plan job 下发）。
  // 不传则用北京时间今天。锚定它的原因：号池大到一晚跑不完时会分成多波，
  // 若跨过午夜，各波会算出不同的轮转偏移 —— 那样有的歌被听两遍、有的没人听。
  const today = /^\d{4}-\d{2}-\d{2}$/.test(dayStr || '') ? dayStr : beijingDate();
  // 两群共用一个 D1：歌环与听众环都按「全池」计算，本 worker 只投递自己群的那批号。
  // 这样跨群互听继续有效（主群的号也会听到定制群的歌），且两边算出的计划完全一致。
  // 注意 SELECT 里那个 hasck：只回 0/1，用来判断「这条能不能播」，比把 ck 整列拉回来省 200 倍传输。
  const rows = await d1All("SELECT pool,uid,name,song,no_listen,added,exp,"
    + "(CASE WHEN ck IS NULL OR TRIM(ck)='' THEN 0 ELSE 1 END) AS hasck "
    + "FROM accounts ORDER BY pool, uid");
  if (rows) return buildPlanFrom(rows.map(planRow), today);
  // 2026-10-22：D1 不可用时用 KV 逐号备份兜底（以前直接返回失败 → run.py 回退到冻结的
  // Secrets 分片，1500 号时那一晚只有 212 个号在跑，而且 job 还是绿的）。
  // KV 里只有本群的号，跨群互听会退化成「只听本群」，但绝不会变成 0 个号。
  console.error('D1 查询失败，buildPlan 回退 KV 逐号备份');
  try {
    const kv = await mergePoolKV();
    if (kv && kv.length) {
      const plan = buildPlanFrom(kv.map(planRow), today);   // KV 行自带 ck，planRow 会判空
      plan.src = 'kv';
      return plan;
    }
  } catch (e) { console.error('buildPlan 的 KV 兜底也失败:', e && e.message); }
  return { ok: false, msg: 'D1 未绑定或查询失败，且 KV 兜底无数据' };
}

async function handle(request) {
    const url = new URL(request.url);
    // 2026-10-25：网页口令统一闸门（KV PAGE_PASS，未配置则不启用）。只拦网页，/api/* 一律放行 ——
    // APK/EXE 直接调接口，加口令会让软件全线失效。
    if (PAGE_ROUTES.has(url.pathname)) {
      const gate = await pageGate(request, url);
      if (gate) return gate;
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      // 2026-10-22：页面里「号池上限 N 人」原来硬编码 200、再靠字符串替换成 KV 里的值 ——
      // 文案一改就静默失效。改成模板占位符 __POOL_LIMIT__，只替换占位符，文案随便改都不影响。
      let lim = 1200;
      try { lim = parseInt(cleanKV(await POOL.get('POOL_LIMIT_G1')), 10) || 1200; } catch (e) {}
      return new Response(INDEX_HTML.replace('__POOL_LIMIT__', String(lim)),
        { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    // ---- 群主管理后台（只读）：ADMIN_PASS 独立口令，NOT 群口令 ----
    if (url.pathname === '/admin' && request.method === 'GET') {
      return new Response(ADMIN_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    // ---- 手动触发 snap650 补采（2026-10-24）：口令同 ASSIGN_PASS，只接受 POST ----
    // 日常由 CF 原生 cron 走 scheduled 自动触发；这个入口只用于人工补跑和排障（查 cron 有没有生效）。
    if (url.pathname === '/api/cron_snap') {
      const c0 = await cfg();
      if (!c0.assignPass) return json({ message: '尚未配置 ASSIGN_PASS，该接口不开放' }, 503);
      if (request.method !== 'POST') return json({ message: '请用 POST' }, 405);
      if ((url.searchParams.get('pass') || '') !== c0.assignPass) return json({ message: '口令错误' }, 403);
      return json(await dispatchSnap650(url.searchParams.get('pool') || 'all'));
    }
    // 本地后台网页（号池管理网页.html）跨域调用本接口：放开 CORS 并处理预检
    // ---- 客服名单 + 套餐档位（2026-10-27 新增）----
    // APK / EXE 每次登记前拉一次；名单改在控制台「客服名单」里，改完客户端下次拉就变，不用重发软件。
    // 不含任何账号信息，故不鉴权（登记接口本来就是公开的）。
    if (url.pathname === '/api/agents') {
      const CORS = { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' };
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type' } });
      if (request.method !== 'GET') return json({ message: '请用 GET' }, 405, CORS);
      const rc = await regCfg();
      return json({ ok: true, agents: rc.agents, plans: rc.plans, at: new Date().toISOString() }, 200, CORS);
    }
    if (url.pathname === '/api/pool' && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      } });
    }
    if (url.pathname === '/api/pool' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const c = await cfg();
      if (!c.adminPass) return json({ message: '尚未设置管理密码：请在 Cloudflare KV 中添加 ADMIN_PASS 键（任意长随机字符串）' }, 503, CORS);
      if (!body.pass || body.pass !== c.adminPass) return json({ message: '管理密码错误' }, 403, CORS);
      const pr = await pruneExpired();
      const master = pr.master;
      // 只回展示字段，绝不下发 ck（cookie）等敏感数据
      const entries = master.map(e => ({
        name: e.name || '', uid: e.uid != null ? String(e.uid) : '',
        song: e.song != null ? String(e.song) : '', added: e.added || '',
        email: e.email || '', phone: e.phone || '', noListen: !!e.noListen, exp: e.exp || '',
      }));
      const stats = {
        total: entries.length,
        withMail: entries.filter(e => e.email).length,
        noMail: entries.filter(e => !e.email).length,
        noListen: entries.filter(e => e.noListen).length,
        public: entries.filter(e => !e.song).length,
        expiring: entries.filter(isSoonExpired).length,
        manual: entries.filter(e => String(e.name).indexOf('manual:') === 0).length,
        limit: c.poolLimitG1,
        remain: Math.max(0, c.poolLimitG1 - entries.length),
      };
      return json({ ok: true, stats: stats, entries: entries }, 200, CORS);
    }
    // ---- 跨群互听歌单（2026-10-20）：只回"可以被听到的歌曲 id"，绝不回任何账号/cookie 信息。
    //      互助群与定制群互相拉这份列表，把两边的歌并成一个歌池，但两个 KV 号池独立、人数各算各的。
    //      口令走 KV 键 PEER_PASS（两边设同一个值）；未设置则该接口不开放。
    if (url.pathname === '/api/songs' && request.method === 'GET') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      // 2026-10-26：口令优先 PEER_KEY（独立 32 位随机，两群同一个值），未配置才回退旧的 PEER_PASS。
      const c = await cfg();
      if (!(await peerPassOk(url.searchParams.get('pass')))) {
        const anyKey = (await peerKey()) || cleanKV(await POOL.get('PEER_PASS'));
        if (!anyKey) return json({ message: '未开启跨群互听：请在 KV 添加 PEER_KEY 键' }, 503, CORS);
        return json({ message: '口令错误' }, 403, CORS);
      }
      // 2026-10-22：这里原来调 pruneExpired()（= 全量重建 + 删键 + 写 master + 推 12 个 Secret）。
      // 但这是「取歌单」这种只读高频接口，不该带写副作用。改为单条 SELECT DISTINCT，
      // 过期号由 /api/pool（管理后台）或 resync 之类管理动作去清。
      let songs;
      const rows = d1ok()
        ? await d1All("SELECT DISTINCT song FROM accounts WHERE pool=? AND song<>'' ORDER BY song", [POOL_NAME])
        : null;
      if (rows) songs = rows.map(r => String(r.song)).filter(Boolean);
      else songs = (await mergePool()).map(e => String(e.song || '')).filter(Boolean);
      songs = [...new Set(songs)].sort();
      return json({ ok: true, count: songs.length, songs: songs }, 200, CORS);
    }
    // ---- D1 分配接口（2026-10-22 新增）：run.py 直接问「本班跑哪些号、每号听什么」----
    if ((url.pathname === '/api/assign' || url.pathname === '/api/pool_stat') && request.method === 'GET') {
      const c = await cfg();
      const pass = url.searchParams.get('pass') || '';
      // 2026-10-22 安全修正：本接口会回明文 CK，绝不能再用「发给全体成员的群口令」鉴权
      //（否则任何成员循环 job=0..N 就能拖走全池 MUSIC_U）。只认独立键 ASSIGN_PASS；
      // 管理密码 ADMIN_PASS 仍放行，方便手工排错。
      if (!c.assignPass) return json({ ok: false, message: '未配置分配口令（KV 键 ASSIGN_PASS），D1 分配接口未开放' }, 503);
      const okPass = pass === c.assignPass;
      const okAdmin = c.adminPass && pass === c.adminPass;
      if (!okPass && !okAdmin) return json({ ok: false, message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const t0 = Date.now();
      if (url.pathname === '/api/pool_stat') {
        const plan = await buildPlan(url.searchParams.get('day'));
        if (!plan.ok) return json({ ok: false, message: plan.msg }, 503);
        const mine = plan.plans.filter(x => x.pool === POOL_NAME).length;
        const idleN = (plan.idle || []).filter(x => x.pool === POOL_NAME).length;
        return json({ ok: true, pool: POOL_NAME, day: plan.day, m: plan.m, l: plan.l,
                      p: plan.p, m_pool: mine, idle: idleN, src: plan.src || 'd1', ms: Date.now() - t0 });
      }
      const job = Math.max(0, parseInt(url.searchParams.get('job') || '0', 10) || 0);
      const jobs = Math.max(1, parseInt(url.searchParams.get('jobs') || '1', 10) || 1);
      if (job >= jobs) return json({ ok: false, message: 'job 超出范围' }, 400);
      const plan = await buildPlan(url.searchParams.get('day'));
      if (!plan.ok) return json({ ok: false, message: plan.msg }, 503);
      const ownPool = plan.plans.filter(x => x.pool === POOL_NAME);
      const mine = ownPool.filter((_, i) => i % jobs === job);
      // 只收不听的号（no_listen）以前完全不进 assign → 不签到、不查工作台、不验活、死了也不报。
      // 现在按同一套 i % jobs 分片下发给各片，run.py 只让它们查工作台/上报，不参与播放。
      const ownIdle = (plan.idle || []).filter(x => x.pool === POOL_NAME);
      const mineIdle = ownIdle.filter((_, i) => i % jobs === job);
      // D1 主路径为省传输没查 ck/email，这里按本片那几个号补一次；KV 兜底路径自带 ck，不会触发。
      const meta = {};
      const need = mine.concat(mineIdle).filter(x => !x.ck);
      // 2026-10-24 修复：D1 单条 SQL 最多 100 个绑定参数（实测 101 个即报
      // "too many SQL variables"）。snap650 用 jobs=1 拉全池（200+ 号）时，
      // 这里拼出 220+ 个 ? → 整条查询失败 → 补不到 ck → 接口返回 0 个号，
      // 上午 10:00 的 650 补采从上线起就没成功过。改为每批 90 个 uid 分次查。
      // 正常播放路径 jobs=250（每片 1-2 个号）仍只跑一次循环，行为不变。
      for (let i = 0; i < need.length; i += 90) {
        const uids = need.slice(i, i + 90).map(x => x.uid);
        const ph = uids.map(() => '?').join(',');
        const rs = await d1All('SELECT uid,name,ck,email FROM accounts WHERE pool=? AND uid IN (' + ph + ')',
                               [POOL_NAME].concat(uids));
        for (const r of (rs || [])) meta[String(r.uid)] = r;
      }
      const pack = x => {
        const m = x.ck ? x : (meta[x.uid] || {});
        return { uid: x.uid, name: m.name || x.name || '', ck: m.ck || x.ck || '',
                 email: m.email || x.email || '', song: x.song || '', plays: x.plays || [] };
      };
      // 只返回真正带 CK 的号（历史占位行 CK 为空，下发过去也只会白跑一次验活）
      const accounts = mine.map(pack).filter(x => x.ck);
      const idle = mineIdle.map(pack).filter(x => x.ck);
      return json({ ok: true, pool: POOL_NAME, day: plan.day, m: plan.m, l: plan.l, p: plan.p,
                    m_pool: ownPool.length, jobs: jobs, job: job, src: plan.src || 'd1',
                    accounts: accounts, idle: idle, ms: Date.now() - t0 });
    }
    // ---- D1 全量对齐（管理员）：把 KV 当前权威数据整表同步到 D1 ----
    if (url.pathname === '/api/d1_sync' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.adminPass || body.pass !== c.adminPass) return json({ message: '管理密码错误' }, 403);
      if (!d1ok()) return json({ message: 'D1 未绑定' }, 503);
      const master = await mergePoolKV();   // 必须读 KV 原文，否则等于 D1 对齐 D1
      let ok = 0, skip = 0, fail = 0;
      for (const e of master) {
        if (e.uid == null || String(e.uid) === '') { skip++; continue; }
        if (await d1Upsert(e)) ok++; else fail++;
      }
      const live = new Set(master.filter(e => e.uid != null).map(e => String(e.uid)));
      const rows = await d1All('SELECT uid FROM accounts WHERE pool=?', [POOL_NAME]) || [];
      // 'name:xxx' 是「没有 uid 的老条目」的占位主键，不在 live 里但绝不能删。
      const gone = rows.filter(r => !String(r.uid).startsWith('name:') && !live.has(String(r.uid)));
      await Promise.all(gone.map(r => d1Run('DELETE FROM accounts WHERE pool=? AND uid=?', [POOL_NAME, String(r.uid)])));
      try { await refreshPoolSnap(); } catch (e) {}   // D1 全表刚被重写 → 同步刷新应急快照
      return json({ ok: true, pool: POOL_NAME, kv: master.length, synced: ok, skipped: skip,
                    failed: fail, removed: gone.length });
    }
    // ---- 管理端账号维护（本地管理页专用）：删除 / 修改（CK、邮箱、歌曲、有效期、暂停互听）----
    if (url.pathname === '/api/admin/entry' && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      } });
    }
    if (url.pathname === '/api/admin/entry' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const c = await cfg();
      if (!c.adminPass) return json({ message: '尚未设置管理密码' }, 503, CORS);
      if (!body.pass || body.pass !== c.adminPass) return json({ message: '管理密码错误' }, 403, CORS);
      // 2026-10-22：编辑逻辑抽成 applyEntryEdit，供本路由与控制台编辑接口 /api/console/entry 共用（行为不变）
      return applyEntryEdit(body);
    }
    if (url.pathname === '/api/join_manual' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      const gp2 = groupPassCheck(c, body);
      if (!gp2.ok) return json({ message: gp2.msg }, gp2.status);
      // 号池满员闸口（防止绕过网页登记直接灌号）；一律按一群计数
      const isG2 = false;
      const myLimit = groupLimitOf(c, isG2);
      const _m2 = await mergePool();
      const grpUsed = activePoolSize(_m2);   // 排除已过期未清的号，口径一致
      if (grpUsed >= myLimit) return json({ message: '本群名额已满（上限 ' + myLimit + ' 人），暂停登记。已有账号的互听和签到不受影响，请稍后再试或联系群主。' }, 429);
      const mu = (body.musicU || '').trim();
      if (!mu) return json({ message: '请填写 MUSIC_U' }, 400);
      const email = (body.email || '').trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ message: '请填写常用邮箱' }, 400);
      const v = await validateCookie(mu);
      if (!v.ok) return json({ message: v.msg }, 400);
      // 2026-10-26 修复：网易接口连续不可达时 validateCookie 会用 blake2b「编造」一个 uid 放行
      // （provisional），编造的 uid 与真实 uid 不同 → 网络恢复后同一账号可能被重复登记两条，
      // 而且任何人都能拿任意 80+ 位 hex 串占名额。这条兜底只对管理员通道开放。
      if (v.provisional) {
        const isAdminReg = !!(c.adminPass && String(body.pass || '') === c.adminPass);
        if (!isAdminReg) {
          return json({ message: '网易校验接口暂时不可达（' + (v.diag || '网络异常') + '），为避免登记出错号，请稍后重试。' }, 503);
        }
      }
      const song = await resolveSong(body.link);
      if (!song.ok) return json({ message: song.msg }, 400);
      const expQ = parseExpInput(body.exp);
      if (!expQ.ok) return json({ message: '有效期格式不对：填天数(如730)、日期(2028-10-18)或不填（默认2年）' }, 400);
      const phoneRaw = (body.phone || '').replace(/[^0-9]/g, '');
      const phone = /^1\d{10}$/.test(phoneRaw) ? phoneRaw : '';
      // 2026-10-27：客服 + 套餐（口径同 /api/join）
      const rc2 = await regCfg();
      const pl2 = planOf(rc2, body.plan);
      const r = await addEntry({ ck: 'MUSIC_U=' + mu, song: song.song, added: beijingDate(), name: phone || ('manual:' + v.uid), uid: v.uid, email: email, phone: phone, grp: isG2 ? 2 : 1, exp: expQ.exp || (pl2 ? pl2.exp : undefined),
        agent: normAgent(body.agent), plan: pl2 ? pl2.label : normAgent(body.plan).slice(0, 8) });
      if (!r.ok) return json({ message: r.msg }, 400);
      let msg = '登记成功，次日生效。';
      if (v.provisional) msg += '（注：网易校验接口暂时不可达[' + (v.diag || '') + ']，已跳过在线校验；明天任务会自动复验）';
      return json({ message: msg });
    }
    // ---- 补录/修改通知邮箱（老号自助通道，只改 email 一个字段，其余原样）----
    if (url.pathname === '/api/updatemail' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      const gp3 = groupPassCheck(c, body);
      if (!gp3.ok) return json({ message: gp3.msg }, gp3.status);
      // 2026-10-26 补频控：本接口只要手机号对得上就能改邮箱，没有任何验证。
      // 这是给「老号补录/换邮箱」用的自助通道，不能加验证码（会打断正常补录），
      // 但必须挡住脚本批量撞号：按出口 IP 每天 20 次。D1 不可用时回退 KV，绝不让频控静默失效。
      const ip = String(request.headers.get('CF-Connecting-IP') || 'unknown').slice(0, 64);
      let hits = await d1Hit('um', ip + ':' + beijingDate());
      if (hits === null) {
        try {
          const rk = 'um:' + ip + ':' + beijingDate();
          const cnt = parseInt(await POOL.get(rk), 10) || 0;
          hits = cnt + 1;
          if (cnt < 20) await POOL.put(rk, String(hits), { expirationTtl: 172800 });
        } catch (e) { hits = 0; }
      }
      if (hits > 20) return json({ message: '今天修改邮箱的次数过多，请明天再试或联系群主。' }, 429);
      const email = (body.email || '').trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ message: '请填写常用邮箱' }, 400);
      const phone = (body.phone || '').replace(/[０-９]/g, c => String.fromCharCode(c.charCodeAt(0) - 65248)).replace(/[^0-9]/g, '');
      const mu = (body.mu || '').trim();
      if (!phone && !mu) return json({ message: '请填写手机号或 MUSIC_U（至少填一个）' }, 400);
      const master = await mergePool();
      let target = null;
      if (mu) {
        const v = await validateCookie(mu);
        if (!v.ok) return json({ message: v.msg }, 400);
        target = master.find(e => e.uid != null && String(e.uid) === String(v.uid)) || null;
      } else {
        target = master.find(e => e.name === phone) || null;
      }
      if (!target) return json({ message: '没有找到你的登记记录：请检查手机号/MUSIC_U 是否填错；如果还没登记过，请用上方的登记方式。' }, 404);
      // 2026-10-26：留一条审计痕迹（谁/何时/把哪个号从什么邮箱改成了什么）。
      // Worker 日志（wrangler tail / CF 面板）可查，出纠纷时能定位。
      console.log('updatemail', JSON.stringify({ ip, key: entryKeyOf(target), uid: String(target.uid != null ? target.uid : ''), from: String(target.email || ''), to: email, at: new Date().toISOString() }));
      target.email = email;
      // 与 addEntry 同一套写入机制：独立键权威写 + master 缓存刷新 + 同步号池 Secrets
      await POOL.put(entryKeyOf(target), JSON.stringify(target));
      // 2026-10-22 修复：这里原先只写 KV，但所有读路径（控制台/管理后台/下次编辑）都已切到 D1，
      // 结果成员自助改的邮箱第二天就被 D1 里的旧值覆盖回去，等于没改。必须同步镜像到 D1。
      if (!(await d1Upsert(target))) {
        console.error('改邮箱的 D1 镜像失败（KV 已写入，可用 /api/resync 补齐）');
      }
      const updated = master.map(e => entryKeyOf(e) === entryKeyOf(target) ? target : e);
      // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
      await pushPool(updated);
      try { await refreshPoolSnap(); } catch (e) {}
      return json({ message: '已保存：' + email + '。之后账号有变化，会发邮件到这个邮箱。' });
    }
    // ---- 二维码登录通道（实测网易是否放行 CF 机房 IP）----
    // GET /api/qr_key  → 网易申请 unikey
    // GET /api/qr_check?key=xxx → 轮询：800过期/801等待/802已扫/803成功（成功时从 set-cookie 提取 MUSIC_U 放进 JSON 返回）
    if (url.pathname === '/api/qr_key' && request.method === 'GET') {
      const r = await fetch(BASE + '/api/login/qrcode/unikey', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA, 'Referer': BASE + '/' },
        body: 'type=1',
      });
      const text = await r.text();
      return new Response(text, { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (url.pathname === '/api/qr_check' && request.method === 'GET') {
      const key = (url.searchParams.get('key') || '').trim();
      if (!key) return json({ message: '缺少 key' }, 400);
      const r = await fetch(BASE + '/api/login/qrcode/client/login?key=' + encodeURIComponent(key) + '&type=1', {
        headers: { 'User-Agent': UA, 'Referer': BASE + '/' },
      });
      const text = await r.text();
      let out = text;
      try {
        const j = JSON.parse(text);
        if (j.code === 803) {
          const sc = r.headers.get('set-cookie') || '';
          const m = sc.match(/MUSIC_U=([^;]+)/);
          j.musicU = m ? m[1] : '';
          out = JSON.stringify(j);
        }
      } catch (e) { /* 非 JSON（被风控页拦截）原样返回，前端据此判失败 */ }
      return new Response(out, { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    // 隐藏管理接口：仍用 GROUP_PASS 保护（2026-10-20 登记接口已去掉群口令，此口令降级为群主管理专用暗号），从 KV 主表重新把 NB_POOL_1..5 推回 GitHub Secrets（KV 丢失/Secrets 异常时一键恢复）
    if (url.pathname === '/api/resync' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      // 2026-10-22：补 `!c.groupPass` —— 以前 KV 里没配 GROUP_PASS 时，body.pass="" 即可通过
      // 2026-10-26：改用 adminPassOk —— 配了 ADMIN_PASS 就只认管理口令，不再接受群口令
      if (!adminPassOk(c, body.pass)) return json({ message: '管理口令错误' }, 403);
      let master = await mergePool();
      await pushPool(master, true);   // 强制推：resync 就是「现在就要一份全量快照到 Secrets」
      return json({ message: `已从 KV 重新同步 ${master.length} 条到 GitHub Secrets（NB_POOL_1..${12}）。` });
    }
    // 失效账号清理：Actions 跑完发现 cookie 失效的号，按 name/uid 从号池剔除并重写分片
    if (url.pathname === '/api/report_dead' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      // 2026-10-26：改用 adminPassOk —— 这是「能删号」的接口，绝不能再认半公开的群口令
      if (!adminPassOk(c, body.pass)) return json({ message: '管理口令错误' }, 403);
      const deadSet = new Set((body.dead || []).map(x => String(x)));
      if (!deadSet.size) return json({ message: '没有需要清理的账号。' });
      const master = await mergePool();
      const before = master.length;
      const deadEntries = master.filter(e => deadSet.has(String(e.name)) || deadSet.has(String(e.uid)));
      if (!deadEntries.length) return json({ message: `没有匹配到账号（号池 ${before} 个）。` });

      // ---- 死号判定（2026-10-23 改版：客户端重试 + 立即删除）----
      // 旧逻辑（2026-10-22）：第一次判死只打 suspect_at，隔 18~36 小时下一轮再判死才真删。
      // 问题：号主要白等一整天，期间「已判死但还挂在池子里」的号既不能听也不能被听，
      // 客服也没法提前帮他重新登记。
      // 新逻辑：客户端（run.py）在判死前已经重试过 3 次（要求至少 2 次明确失效），
      // 确认之后带 confirm=true 上报 → 服务端直接删号；客户端随即给号主发「账号信息过期」邮件。
      // 也就是说「确认」这一步从服务端的时间窗口挪到了客户端的重试，效果等价但不用等一天。
      // 不带 confirm 的旧客户端仍走原来的 suspect_at 双重确认，向后兼容。
      const forceConfirm = body.confirm === true;
      const susRows = forceConfirm ? null
        : await d1All('SELECT uid,suspect_at FROM accounts WHERE pool=?', [POOL_NAME]);
      const susMap = {};
      if (susRows) for (const r of susRows) susMap[String(r.uid)] = String(r.suspect_at || '');
      const nowMs = Date.now();
      const suspects = [], confirmed = [];
      for (const e of deadEntries) {
        if (forceConfirm) { confirmed.push(e); continue; }   // 客户端已重试确认 → 直接删
        if (!susRows) { suspects.push(e); continue; }        // D1 读不到 → 无法确认，保守只打标不删
        const prev = susMap[String(e.uid)] || '';
        const t = prev ? Date.parse(prev) : NaN;
        const ageH = isNaN(t) ? -1 : (nowMs - t) / 3600000;
        if (ageH >= 18 && ageH <= 36) confirmed.push(e); else suspects.push(e);
      }
      const stamp = new Date(nowMs).toISOString();
      if (susRows) {
        for (const e of suspects) {
          await d1Run('UPDATE accounts SET suspect_at=? WHERE pool=? AND uid=?', [stamp, POOL_NAME, String(e.uid)]);
        }
      }
      // 删除走独立键（单键删除，无竞态），并记墓碑防缓存复活；再刷新 master 缓存
      const deadEkeys = confirmed.map(e => entryKeyOf(e));
      await Promise.all(confirmed.map(e => POOL.delete(entryKeyOf(e))));
      try { await Promise.all(confirmed.map(e => d1Delete(e))); } catch (e) { console.error('D1 清理镜像失败:', e && e.message); }
      if (deadEkeys.length) {
        try {
          const log = new Set(await getDeadLog());
          for (const k of deadEkeys) log.add(k);
          // 只留最近 500 条，防止无限增长
          await POOL.put('dead_log', JSON.stringify([...log].slice(-500)));
        } catch (e) {}
      }
      await d1LogDead(confirmed, 'cookie_invalid');
      const gone = new Set(deadEkeys);
      const after = master.filter(e => !gone.has(entryKeyOf(e)));
      // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
      await pushPool(after);
      try { await refreshPoolSnap(); } catch (e) {}
      const nm = arr => arr.map(e => e.name || e.uid).join('、');
      // deleted：真正被删掉的号名。run.py 靠它决定「给谁发过期邮件」——
      // 只有删成功了才发，避免「邮件说已删除、号其实还在池里」。
      const deleted = confirmed.map(e => e.name || String(e.uid));
      return json({ ok: true, deleted: deleted,
        message: `本次确认清理 ${confirmed.length} 个${confirmed.length ? '（' + nm(confirmed) + '）' : ''}；`
        + `新增疑似 ${suspects.length} 个（需下一轮再次判死才删除${suspects.length ? '：' + nm(suspects) : ''}），`
        + `剩余 ${after.length} 个。` });
    }
    // ====================================================================
    // 手动删号的「通知号主」判定队列（2026-10-26 新增，纯新增路由）
    // 为什么要单独一套：控制台删号是在 worker 里直接删 D1 行完成的，没有 Python 进程
    //   参与，而 smtp.qq.com:465 只能从 GitHub Actions 发 → 手动删号的号主一封邮件都收不到。
    // 为什么不能无脑发：实测最近 12 条 manual 里 7 条是 hz→dz 迁移、2 条是删了当天重登，
    //   只有 3 条真离开系统。给前 9 位发「账号信息过期，麻烦重新登记」纯属误报（他们号好好的）。
    // 判定口径（用户 2026-10-26 定）：删除时入队(pending) → 等满 12 小时 → 再判
    //   ① 同 uid 或同账号名在任一池又出现了 → 迁移/重登 → 不发（skip_returned）
    //   ② 没留邮箱 → 不发（skip_noemail）
    //   ③ 其余视为真删 → 返回给 Actions，由 notify.py 发那封现成模板
    // 并发保护：判完立刻标 claimed；发信成功后回调 /api/dead_sent 标 sent，失败回调 retry
    //   退回 pending；claimed 超过 2 小时自动回 pending（runner 中途挂掉不至于永久卡住）。
    // ====================================================================
    if (url.pathname === '/api/dead_pending' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (body.pass !== c.assignPass && !(c.adminPass && body.pass === c.adminPass)) return json({ message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const waitH = Math.max(0, Number(body.wait_h != null ? body.wait_h : 12) || 0);
      const nowMs = Date.now();
      const cutoff = bjStamp(nowMs - waitH * 3600000);
      // claimed 卡住超过 2 小时的回退，避免 runner 挂死把这批永久占住
      await d1Run("UPDATE dead_notice SET state='pending',claimed_at=NULL WHERE state='claimed' AND claimed_at<=?",
        [bjStamp(nowMs - 2 * 3600000)]);
      const pend = await d1All(
        'SELECT pool,uid,name,email,removed_at FROM dead_notice WHERE state=? AND removed_at<=? ORDER BY removed_at LIMIT 100',
        ['pending', cutoff]) || [];
      const toSend = [], skipped = [];
      for (const r of pend) {
        const uid = String(r.uid || ''), nm = String(r.name || '');
        // 「回来了吗」：同 uid 或同账号名出现在任一池（hz/dz 都算）→ 迁移或重登，不该发
        let back = '';
        const conds = [], vals = [];
        if (uid) { conds.push('uid=?'); vals.push(uid); }
        if (nm) { conds.push('name=?'); vals.push(nm); }
        if (conds.length) {
          const q = await d1All('SELECT pool FROM accounts WHERE ' + conds.join(' OR ') + ' LIMIT 1', vals);
          if (q && q.length) back = String(q[0].pool || '');
        }
        if (back) { skipped.push({ pool: r.pool, uid: uid, name: nm, removed_at: r.removed_at, state: 'skip_returned', why: '已在 ' + back + ' 池' }); continue; }
        const em = String(r.email || '').trim();
        if (!em) { skipped.push({ pool: r.pool, uid: uid, name: nm, removed_at: r.removed_at, state: 'skip_noemail', why: '未登记邮箱' }); continue; }
        toSend.push({ pool: r.pool, uid: uid, name: nm, email: em, removed_at: String(r.removed_at) });
      }
      const stamp = bjStamp();
      const isDry = body.dry === true;   // 干跑：只返回名单，不改任何状态（核对用）
      if (!isDry) {
        for (const s of skipped) {
          await d1Run('UPDATE dead_notice SET state=?,skip_reason=?,claimed_at=? WHERE pool=? AND uid=? AND removed_at=?',
            [s.state, s.why, stamp, s.pool, s.uid, s.removed_at]);
        }
        for (const s of toSend) {
          await d1Run("UPDATE dead_notice SET state='claimed',claimed_at=? WHERE pool=? AND uid=? AND removed_at=?",
            [stamp, s.pool, s.uid, s.removed_at]);
        }
      }
      return json({ ok: true, dry: isDry, wait_h: waitH, cutoff: cutoff, to_send: toSend, skipped: skipped });
    }
    // 发信结果回写：sent = 已发；retry = 本轮失败，退回 pending 下次再试
    if (url.pathname === '/api/dead_sent' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (body.pass !== c.assignPass && !(c.adminPass && body.pass === c.adminPass)) return json({ message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const items = (body.items || []).slice(0, 200);
      const retry = body.result === 'retry';
      const stamp = bjStamp();
      let n = 0;
      for (const it of items) {
        const ok = retry
          ? await d1Run("UPDATE dead_notice SET state='pending',claimed_at=NULL,sent_at=NULL WHERE pool=? AND uid=? AND removed_at=?",
            [String(it.pool || ''), String(it.uid || ''), String(it.removed_at || '')])
          : await d1Run("UPDATE dead_notice SET state='sent',sent_at=? WHERE pool=? AND uid=? AND removed_at=?",
            [stamp, String(it.pool || ''), String(it.uid || ''), String(it.removed_at || '')]);
        if (ok) n++;
      }
      return json({ ok: true, updated: n, result: retry ? 'retry' : 'sent' });
    }
    // ====================================================================
    // 进阶控制台（2026-10-22 新增，全部为纯新增路由，不改动任何既有路由）
    // 页面 /console；数据流：两群 run.py 播完顺带查工作台 → POST /api/snap 归口本 worker KV
    //（key: snap:<日期>:<pool>:<分片>，90 天过期）→ 控制台按日期聚合展示 + 日环比 + 编辑。
    // 登录：账号/密码均 xx1031（可在 KV 加 CONSOLE_PASS 键覆盖默认密码；用户名固定 xx1031）。
    // ====================================================================
    if (url.pathname === '/console' && request.method === 'GET') {
      // 2026-10-25：打开页面顺手在后台补一批歌曲/账号元数据（不阻塞响应、失败静默）
      try { if (globalThis.CTX && typeof globalThis.CTX.waitUntil === 'function') globalThis.CTX.waitUntil(backfillMeta()); } catch (e) {}
      return new Response(CONSOLE_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (url.pathname === '/api/console/login' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      // 2026-10-27：登录返回 role（full=满权限 / ro=只读）。页面据此把「编辑、删号、客服名单」
    // 这些写入口全部关掉；真正的拦截在服务端写接口上，前端只是不让人白点。
      const role = await consoleRole(body);
      return json(role ? { ok: true, role: role } : { ok: false, message: '账号或密码错误' }, role ? 200 : 403, CORS);
    }
    // 快照写入（run.py 每个分片跑完后上报一次；两群归口本 KV）
    if (url.pathname === '/api/snap' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const c = await cfg();
      const pass = String(body.pass || '');
      const pool = body.pool === 'dz' ? 'dz' : 'hz';
      // 鉴权：主群走本群群口令；定制群走跨群对穿口令（本 worker 的 PEER_PASS 键里存的就是定制群口令）
      if (pool === 'dz') {
        const peerPass = cleanKV(await POOL.get('PEER_PASS'));
        if (!peerPass || pass !== peerPass) return json({ message: '口令错误' }, 403, CORS);
      } else {
        if (!c.groupPass || pass !== c.groupPass) return json({ message: '口令错误' }, 403, CORS);
      }
      const date = /^\d{4}-\d{2}-\d{2}$/.test(body.date || '') ? body.date : beijingDate();
      const slice = String(body.slice == null ? 'x' : body.slice).replace(/[^\w-]/g, '').slice(0, 8) || 'x';
      const accs = (body.accs && typeof body.accs === 'object') ? body.accs : {};
      const clean = {};
      // 2026-10-26 新增：data 层 furtherVipGetTime 旁路留档（run.py workbench_info 的 periodEnd）。
      // ⚠️ 实测该字段【不是当前任务周期的结束日】（10-26 全池验证：按它判「已过期」的号 95% 仍在涨），
      // 所以只存不判，控制台的「周期归零」仍用「昨日≥80%」的启发式。别拿它当到期日。
      // 为什么不塞进 clean：clean 会原样写进 D1 snapshots 表，多一个字段就撞「列不存在」。
      // 只在上午补采（slice=am）这一路收集，避免凌晨 250 个分片并发读改写同一个 KV 键。
      const perIn = {};
      const collectPeriod = (slice === 'am');
      for (const k of Object.keys(accs).slice(0, 300)) {
        const a = accs[k] || {};
        clean[String(k).slice(0, 16)] = {
          rate: a.rate == null ? null : Number(a.rate) || 0,
          rpc30: a.rpc30 == null ? null : Number(a.rpc30) || 0,
          cnt: a.cnt == null ? null : Number(a.cnt) || 0,
          // 2026-10-23 修复：run.py 上报的字段名是 missions，这里原来只读 mis →
          // 「任务」列永远空。两个名字都认，优先 mis。
          mis: (a.mis && typeof a.mis === 'object') ? a.mis
               : ((a.missions && typeof a.missions === 'object') ? a.missions : {}),
          dur: a.dur == null ? null : Number(a.dur) || 0,
        };
        if (collectPeriod) {
          const peRaw = String(a.periodEnd || '');
          if (/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(peRaw)) perIn[pool + '|' + String(k).slice(0, 16)] = peRaw;
        }
      }
      // 时长沉淀：uid→登记歌曲时长(秒)。跟号走不跟日期走，存 console:durs（永不过期，随改随覆盖）。
      // body.durs 供一次性回填用；纯回填（accs 空）时不写当日快照，防止空分片覆盖。
      const incoming = {};
      for (const k of Object.keys(clean)) { if (clean[k].dur) incoming[k] = clean[k].dur; }
      if (body.durs && typeof body.durs === 'object') {
        for (const k of Object.keys(body.durs).slice(0, 500)) {
          const v = Number(body.durs[k]);
          if (v > 0) incoming[String(k).slice(0, 16)] = Math.round(v);
        }
      }
      let dursChanged = 0;
      if (Object.keys(incoming).length) {
        // 2026-10-22：console:durs 是单键，250 片并发 get→put 必然互相覆盖 → 主存储改 D1 durs 表
        //（按 (pool,uid) UPSERT，无竞态）。
        // 2026-10-22 第三批：D1 写成功就不再写 KV。以前不论成败都双写，而 KV「同一个 key 每秒
        // 只能写 1 次」，250 片又是并发上报 → 这份"备份"大部分请求直接 429 失败，白烧当日
        // 1000 次写额度，却根本保不住数据。现在只在 D1 写失败时才落 KV。
        if (d1ok()) dursChanged = await d1DursWrite(pool, incoming);
        if (!dursChanged) {
          try {
            let cur = {};
            try { cur = JSON.parse(await POOL.get('console:durs') || '{}'); } catch (e) {}
            for (const k of Object.keys(incoming)) { if (cur[k] !== incoming[k]) { cur[k] = incoming[k]; dursChanged++; } }
            if (dursChanged) await POOL.put('console:durs', JSON.stringify(cur));
          } catch (e) { /* 时长沉淀失败不影响快照 */ }
        }
      }
      // 周期结束日沉淀（2026-10-26）：跟号走不跟日期走，存 console:period 单键，
      // 键带池前缀（'hz|uid' / 'dz|uid'），防同一个号挂两池时互相覆盖。
      // 只在 slice=am 的补采里写，凌晨 250 片并发上报不碰这个键（KV 单键读改写会互相覆盖）。
      if (Object.keys(perIn).length) {
        try {
          let cur = {};
          try { cur = JSON.parse(await POOL.get('console:period') || '{}'); } catch (e) {}
          const merged = Object.assign({}, cur, perIn);
          const ks = Object.keys(merged);
          if (ks.length > 3000) for (const k of ks.slice(0, ks.length - 3000)) delete merged[k];
          await POOL.put('console:period', JSON.stringify(merged));
        } catch (e) { /* 周期日沉淀失败不影响快照 */ }
      }
      // 实跑名单（2026-10-22）：run.py 把本片真正跑完播放的 uid 一起报上来，
      // 供 /api/coverage 核对「应跑 vs 实跑」。放在空快照提前返回之前，避免只有名单没有指标时丢数据。
      const ranUids = Array.isArray(body.ran) ? body.ran.map(x => String(x)).filter(Boolean).slice(0, 400) : [];
      const ranWrote = ranUids.length ? await d1RunsWrite(date, pool, ranUids, slice) : 0;
      if (!Object.keys(clean).length) {
        return json({ ok: true, dursMerged: dursChanged, ran: ranWrote, note: '纯时长回填，未写快照' }, 200, CORS);
      }
      const key = 'snap:' + date + ':' + pool + ':' + slice;
      // 2026-10-22：主存储改 D1 snapshots 表。
      // 2026-10-22 第三批：D1 写成功就不再写 KV。以前每片每天都写一个 snap: 键，200 片就是
      // 200 次 KV 写/天（免费额度 1000 的 20%），而控制台读早已切到 D1 —— 这份纯粹白烧额度。
      // 现在只有 D1 写失败时才落 KV：真正需要它的时候它才存在。
      const d1okSnap = await d1SnapWrite(date, pool, clean);
      if (!d1okSnap) {
        try {
          await POOL.put(key, JSON.stringify({ ts: new Date().toISOString(), accs: clean }), { expirationTtl: 7776000 });
        } catch (e) {
          return json({ message: '快照写入失败：D1 与 KV 均不可用（' + ((e && e.message) || e) + '）' }, 500, CORS);
        }
      }
      return json({ ok: true, key: key, count: Object.keys(clean).length, ran: ranWrote, d1: d1okSnap,
                    kv_fallback: !d1okSnap }, 200, CORS);
    }
    // ---- 覆盖率核对（2026-10-22 新增）：应跑 vs 实跑 ----
    // 以前没有任何地方核对「这一轮到底跑了多少个号」：250 片里有几片静默失败，job 依旧是绿的。
    // 按天返回「计划听众数 / 实跑号数 / 缺口名单」，由 coverage.yml 每天调一次并发邮件。
    if (url.pathname === '/api/coverage' && request.method === 'GET') {
      const c = await cfg();
      const pass = url.searchParams.get('pass') || '';
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (pass !== c.assignPass && !(c.adminPass && pass === c.adminPass)) return json({ ok: false, message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const day = /^\d{4}-\d{2}-\d{2}$/.test(url.searchParams.get('day') || '')
        ? url.searchParams.get('day') : beijingDate();
      const poolQ = url.searchParams.get('pool') || POOL_NAME;
      const plan = await buildPlan(day);
      if (!plan.ok) return json({ ok: false, message: plan.msg }, 503);
      const expected = plan.plans.filter(x => x.pool === poolQ).map(x => String(x.uid));
      const rows = await d1All('SELECT uid FROM runs WHERE day=? AND pool=?', [day, poolQ]) || [];
      const ranSet = new Set(rows.map(r => String(r.uid)));
      const expSet = new Set(expected);
      const missing = expected.filter(u => !ranSet.has(u));
      const extra = [...ranSet].filter(u => !expSet.has(u));
      return json({ ok: true, day: day, pool: poolQ, expected: expected.length, ran: ranSet.size,
                    missing_n: missing.length, missing: missing.slice(0, 80), extra_n: extra.length,
                    pct: expected.length ? Math.round(ranSet.size * 1000 / expected.length) / 10 : 0 });
    }
    // 控制台数据聚合：两群账号列表（绝不下发 ck）+ 当日与前日快照（供日环比）
    if (url.pathname === '/api/console/data' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const role = await consoleRole(body);
      if (!role) return json({ message: '账号或密码错误' }, 403, CORS);
      const date = /^\d{4}-\d{2}-\d{2}$/.test(body.date || '') ? body.date : beijingDate();
      // 2026-10-27：支持「日期范围」—— 控制台日期框改成「起始 ~ 结束」两个，
      // body.date 仍是结束日（"今天"这一侧，plan/runs/streak/删号等一律按它算），
      // body.prevDate 由前端给起始日；不给就退回「结束日的前一天」（等于原来的单日视图）。
      // 只影响 snap.cur / snap.prev 这两张快照表取哪天，其余字段口径完全不变。
      const prevDate = /^\d{4}-\d{2}-\d{2}$/.test(body.prevDate || '')
        ? (body.prevDate < date ? body.prevDate : dateMinus1(date))
        : dateMinus1(date);
      // 2026-10-22：控制台是高频只读接口，原来每刷新一次就跑 pruneExpired()（全量重建 +
      // 可能删键 + 写 204KB master + 推 12 个 Secret）。改为直接读 D1 全表（一条 SELECT）。
      // 过期号在页面上仍会按 exp 字段标红，真正的清理交给管理后台/resync。
      //
      // 2026-10-23：并发化。原来这一段是 7 段串行 await（鉴权后的读全池 → 读配置 → 读对端地址
      // → fetch 对端 worker → 读今日快照 → 读昨日快照 → 读时长表），实测业务耗时 1.0~1.75s，
      // 其中大部分是这七段 rtt 相加。这些读彼此没有任何依赖（唯一有依赖的是「拉对端账号列表」
      // 需要 cfg().groupPass，单独放在下面），一次 Promise.all 全部发出去即可。
      // 并发不会打爆 D1/KV：每一段都是单条 SELECT 或单键 get。
      // 2026-10-23 第五批（运行状态上控制台，纯加法不改现有字段）：
      //   plan      → buildPlan(date) 拿当天应跑名单（与 /api/coverage 同一口径：plans=listeners）
      //   ranRows   → runs 表实跑名单
      //   deadRows  → D1 dead_log 最近删号记录
      //   suspectRows → accounts.suspect_at!='' 的待复核号（注意空串不是 NULL，不能写 IS NOT NULL）
      //   freshRows → 各池当天快照最后写入时间（数据新鲜度）
      //   actions   → 两仓库最近一次 run.yml 作业状态（fetchActionsStatus 内部带 KV 5 分钟缓存）
      const [master, c2, cur, prev, dr, peerUrlRaw, plan, ranRows, deadRows, suspectRows, freshRows, actions, streakRows, songRows, accRows, noticeRows, deadTodayRows, regCfgNow] = await Promise.all([
        mergePool(),
        cfg(),
        readSnapDay(date),
        readSnapDay(prevDate),
        d1ok() ? d1All('SELECT pool,uid,dur FROM durs') : Promise.resolve(null),
        POOL.get('PEER_URL').catch(() => null),
        buildPlan(date).catch(() => null),
        d1ok() ? d1All('SELECT pool,uid FROM runs WHERE day=?', [date]).catch(() => null) : Promise.resolve(null),
        d1ok() ? d1All('SELECT pool,uid,name,reason,at FROM dead_log ORDER BY at DESC LIMIT 12').catch(() => null) : Promise.resolve(null),
        d1ok() ? d1All("SELECT pool,uid,name,suspect_at FROM accounts WHERE suspect_at!='' ORDER BY suspect_at DESC").catch(() => null) : Promise.resolve(null),
        d1ok() ? d1All('SELECT pool,MAX(at) AS last FROM snapshots WHERE day=? GROUP BY pool', [date]).catch(() => null) : Promise.resolve(null),
        fetchActionsStatus(),
        // 2026-10-23：最近 7 天快照，用于「连续不涨天数」。date-6 起（含当天）；
        // 改造前数据断层天的行不存在，calcStreaks 天然跳过。
        d1ok() ? d1All('SELECT day,pool,uid,rate FROM snapshots WHERE day>=? AND day<=?', [dateMinusN(date, 6), date]).catch(() => null) : Promise.resolve(null),
        // 2026-10-25：歌曲/账号元数据（song_meta / acc_meta，由 tmp/sync_song_meta.py 回填）。
        // 用来判断「共创歌曲（合唱）」「绑错歌（歌曲作者里没有本人音乐人）」这两类售后问题。
        // 纯只读、失败降级为 null，缺数据时页面只是不打这两个标签，不影响其它列。
        d1ok() ? d1All('SELECT song,n_artists,artists,first_artist,gone FROM song_meta').catch(() => null) : Promise.resolve(null),
        d1ok() ? d1All('SELECT uid,artist_id,artist_name FROM acc_meta').catch(() => null) : Promise.resolve(null),
        // 2026-10-26：手动删号的「通知号主」判定状态（dead_notice），只用于在删号记录里
        // 标一行「已通知 / 已回池不发 / 待判」。纯只读，失败降级为 null。
        d1ok() ? d1All('SELECT pool,uid,removed_at,state,sent_at,skip_reason FROM dead_notice ORDER BY removed_at DESC LIMIT 60').catch(() => null) : Promise.resolve(null),
        // 2026-10-26：当日删除全量（不受上面 LIMIT 12 限制），只取 uid/pool 用于
        // 「当日删号」口径判定 —— 删完又登记回来的号不该算成删号。
        // 用 substr 精确匹配那一天：控制台可以切到历史日期，写 at>=date 会把之后几天也算进来。
        d1ok() ? d1All('SELECT pool,uid,reason FROM dead_log WHERE substr(at,1,10)=?', [date]).catch(() => null) : Promise.resolve(null),
        // 2026-10-27：客服名单 + 套餐档位（控制台据此生成筛选下拉、套餐汇总与编辑弹窗选项）。
        // 与上面几段一起并发发出，不额外增加一次串行 rtt。
        regCfg().catch(() => REG_CFG_DEFAULT),
      ]);
      const disp = e => ({
        name: e.name || '', uid: e.uid != null ? String(e.uid) : '',
        song: e.song != null ? String(e.song) : '', added: e.added || '',
        email: e.email || '', phone: e.phone || '', noListen: !!e.noListen, exp: e.exp || '',
        // 2026-10-27：客服标签 + 套餐档位（控制台新增两列 / 顶部套餐汇总 / 按客服筛选的数据源）
        agent: e.agent || '', plan: e.plan || '',
      });
      const hz = master.map(disp);
      // 定制群账号列表：实时向对端 worker 拉（对穿口令；拉失败不阻塞主群展示）
      // ⚠️ 对穿方向：本 worker 的 PEER_PASS 键存的是「定制群口令」，而定制群 worker 的 PEER_PASS 键
      //    存的是「本群口令」——所以调对端接口要用本群群口令 c.groupPass，不是本 worker 的 PEER_PASS。
      let dz = [];
      try {
        const peerUrl = cleanKV(peerUrlRaw) || PEER_DEFAULT;
        // 2026-10-26：优先用独立对穿口令 PEER_KEY；未配置才回退「本群群口令」的老对穿方式。
        const pk = await peerKey();
        const dzPass = pk || c2.groupPass;
        if (dzPass) {
          const r = await fetch(peerUrl.replace(/\/+$/, '') + '/api/peer/pool?pass=' + encodeURIComponent(dzPass), { headers: { 'User-Agent': 'cron-relay-worker' } });
          const d = await r.json();
          if (d && d.ok) dz = (d.entries || []).map(disp);
        }
      } catch (e) { /* 对端不可达：dz 列表留空，页面会提示 */ }
      // 2026-10-22 第三批：D1 可用时不再读 KV 的 console:durs（省一次读，也不会读到旧值）。
      // 只有 D1 不可用时才回退 KV —— 那份现在已经只在 D1 写失败时才会被更新。
      let durs = {};
      if (dr) {
        // 2026-10-23：durs 表主键是 (pool,uid)，同一个号可能同时挂在两个群（实测 7 个），
        // 之前只按 uid 拍平会让两池互相覆盖 → 时长显示成另一个群那首歌的。现在额外写一份
        // 带池前缀的键「hz|uid」，页面优先用它；扁平键保留，兼容老页面与 KV 回退模式。
        for (const r of dr) {
          if (!r.uid || r.dur == null) continue;
          const v = Number(r.dur) || 0;
          const uid = String(r.uid);
          durs[(r.pool === 'dz' ? 'dz' : 'hz') + '|' + uid] = v;
          if (!(uid in durs)) durs[uid] = v;
        }
      } else {
        try { durs = JSON.parse(await POOL.get('console:durs') || '{}'); } catch (e) {}
      }
      // 2026-10-26 新增：furtherVipGetTime 留档（键 'hz|uid' / 'dz|uid' → YYYY-MM-DD）。
      // 只在 slice=am 补采时写入；读失败降级 null。⚠️ 仅数据留档，不参与任何判定
      //（实测它不是当前周期结束日，详见 /api/snap 处说明）。
      let periods = null;
      try { periods = JSON.parse(await POOL.get('console:period') || 'null'); } catch (e) { periods = null; }
      // ---- 2026-10-23 组装运行状态数据（纯加法：全部是新键，不影响 hz/dz/durs/snap）----
      // coverage：应跑 vs 实跑。口径与 /api/coverage 逐字一致（expected=plans 里本池 uid，ran=runs 表）。
      const cov = {};
      if (plan && plan.ok && Array.isArray(plan.plans)) {
        const ranByPool = {};
        for (const r of (ranRows || [])) {
          const p = r.pool === 'dz' ? 'dz' : 'hz';
          (ranByPool[p] = ranByPool[p] || new Set()).add(String(r.uid));
        }
        for (const p of ['hz', 'dz']) {
          const exp = plan.plans.filter(x => x.pool === p).map(x => String(x.uid));
          const ranSet = ranByPool[p] || new Set();
          const missing = exp.filter(u => !ranSet.has(u));
          cov[p] = { expected: exp.length, ran: exp.length - missing.length,
                     missing: missing.slice(0, 80),
                     pct: exp.length ? Math.round((exp.length - missing.length) * 1000 / exp.length) / 10 : 0 };
        }
      }
      // 2026-10-26：通知状态索引（按「池|uid」取最近一条判定）。只覆盖手动删号；
      // cookie_invalid 的号由 run.py 当场发信，不进这张表。
      const noticeMap = {};
      for (const r of (noticeRows || [])) {
        const k = (r.pool === 'dz' ? 'dz' : 'hz') + '|' + String(r.uid || '');
        if (!noticeMap[k]) noticeMap[k] = { state: r.state || '', removed_at: r.removed_at || '', sent_at: r.sent_at || '', why: r.skip_reason || '' };
      }
      const dead = (deadRows || []).map(r => ({ pool: r.pool === 'dz' ? 'dz' : 'hz', uid: String(r.uid || ''),
                                                name: r.name || '', reason: r.reason || '', at: r.at || '',
                                                notice: noticeMap[(r.pool === 'dz' ? 'dz' : 'hz') + '|' + String(r.uid || '')] || null }));
      const suspects = (suspectRows || []).map(r => ({ pool: r.pool === 'dz' ? 'dz' : 'hz', uid: String(r.uid || ''),
                                                       name: r.name || '', since: r.suspect_at || '' }));
      // 2026-10-26：当日删除明细（用于「当日删号」统计）。只给 uid/pool/reason，
      // 前端拿当前号池做差集 —— 还在池里的算「已回池」（迁移/重登），不算真删。
      const deadToday = (deadTodayRows || []).map(r => ({ pool: r.pool === 'dz' ? 'dz' : 'hz',
                                                          uid: String(r.uid || ''), reason: r.reason || '' }));
      const fresh = {};
      for (const r of (freshRows || [])) { fresh[r.pool === 'dz' ? 'dz' : 'hz'] = r.last || ''; }
      // 2026-10-23：连续不涨天数（>=2 天才有条目；查询失败时降级为空字典，页面无标记）
      const streak = calcStreaks(streakRows || []);
      // 2026-10-25：歌曲作者归属（控制台「共创歌曲 / 绑错歌」标签的数据源）
      // songs[song] = {n:作者数, i:[作者id...], f:第一艺人名, g:1=网易查无此歌}
      // artists[uid] = [音乐人id, 音乐人名]；id 为 '' 表示确认该账号不是音乐人
      const songs = {};
      for (const r of (songRows || [])) {
        if (!r || r.song == null) continue;
        let ids = [];
        try { ids = (JSON.parse(r.artists || '[]') || []).map(x => String((x && x[0] != null) ? x[0] : '')); } catch (e) { ids = []; }
        songs[String(r.song)] = { n: Number(r.n_artists) || 0, i: ids, f: r.first_artist || '', g: Number(r.gone) ? 1 : 0 };
      }
      const artists = {};
      for (const r of (accRows || [])) {
        if (!r || r.uid == null) continue;
        artists[String(r.uid)] = [r.artist_id == null ? '' : String(r.artist_id), r.artist_name || ''];
      }
      // 2026-10-25：顺手在后台补几条歌曲/账号元数据（新号登记后自动补，不用再手动跑脚本）
      try { if (globalThis.CTX && typeof globalThis.CTX.waitUntil === 'function') globalThis.CTX.waitUntil(backfillMeta()); } catch (e) {}
      return json({ ok: true, date: date, prevDate: prevDate, hz: hz, dz: dz, durs: durs, snap: { cur: cur, prev: prev },
                    coverage: cov, actions: actions || [], dead: dead, deadToday: deadToday, suspects: suspects, fresh: fresh,
                    streak: streak, songs: songs, artists: artists, periods: periods,
                    // 2026-10-27：role 决定页面要不要把写入口关掉；cfg 供筛选下拉与编辑弹窗用
                    role: role, cfg: regCfgNow }, 200, CORS);
    }
    // 控制台编辑：hz 本地执行（与管理后台同一套逻辑）；dz 转发到对端 worker 的对等接口
    if (url.pathname === '/api/console/entry' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      // 2026-10-27：写接口只认满权限口令（只读口令进来这里一律 403）
      if (!(await consoleAuthFull(body))) {
        const who = await consoleRole(body);
        return json({ message: who === 'ro' ? '当前是只读口令，不能修改账号' : '账号或密码错误' }, 403, CORS);
      }
      if (body.pool === 'dz') {
        try {
          const c3 = await cfg();
          // 2026-10-26：优先用独立对穿口令 PEER_KEY；未配置才回退「本群群口令」的老对穿方式。
          const peerUrl = (cleanKV(await POOL.get('PEER_URL')) || PEER_DEFAULT).replace(/\/+$/, '');
          const fwdPass = (await peerKey()) || c3.groupPass;
          if (!fwdPass) return json({ message: '本 worker 未配置对穿口令（KV 键 PEER_KEY / GROUP_PASS），无法编辑定制群账号' }, 503, CORS);
          const fwd = { pass: fwdPass, action: body.action, uid: body.uid, name: body.name,
            ck: body.ck, link: body.link, email: body.email, exp: body.exp, noListen: body.noListen,
            agent: body.agent, plan: body.plan };
          const r = await fetch(peerUrl + '/api/peer/entry', { method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': 'cron-relay-worker' },
            body: JSON.stringify(fwd) });
          return new Response(r.body, { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
        } catch (e) {
          return json({ message: '转发到定制群失败：' + ((e && e.message) || e) }, 502, CORS);
        }
      }
      return applyEntryEdit(body);
    }
    // 客服名单 / 套餐档位维护（2026-10-27）：只认满权限口令。
    // 只传要改的字段：agents 和 plans 哪个没传就保持原样，避免「只加一个人把套餐表冲掉」。
    if (url.pathname === '/api/console/cfg' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuthFull(body))) {
        const who = await consoleRole(body);
        return json({ message: who === 'ro' ? '当前是只读口令，不能修改客服名单' : '账号或密码错误' }, 403, CORS);
      }
      const cur = await regCfg();
      const next = {
        agents: body.agents !== undefined ? body.agents : cur.agents,
        plans: body.plans !== undefined ? body.plans : cur.plans,
      };
      const saved = await saveRegCfg(next);
      return json({ ok: true, d1: saved.ok, cfg: saved.cfg,
        message: '已保存：客服 ' + saved.cfg.agents.length + ' 人、套餐 ' + saved.cfg.plans.length + ' 档'
          + (saved.ok ? '' : '（⚠️ D1 写入失败，已写 KV 兜底，请稍后重试）') }, 200, CORS);
    }
    return json({ message: 'not found' }, 404);
}

function json(o, status = 200, extraHeaders) { return new Response(JSON.stringify(o), { status, headers: Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {}) }); }

// ---- 控制台登录校验（2026-10-22）：用户名固定 xx1031；密码只认 KV 键 CONSOLE_PASS ----
// 2026-10-22 安全修正：原先未配置 CONSOLE_PASS 时回落到缺省口令 xx1031，等于控制台对外敞开
//（实测匿名可登录、可看全池姓名/uid/邮箱、可删任意账号）。现在未配置 = 不开放，必须显式设置。
// 2026-10-27 新增只读口令：KV 键 CONSOLE_RO_PASS。拿它进来只能看，任何写接口一律 403。
//   返回 'full'（满权限）/ 'ro'（只读）/ null（口令不对）。未配置 = 该档位不存在，
//   所以「没配 CONSOLE_RO_PASS」时只读口令天然用不了，不会退化成谁都能只读。
async function consoleRole(body) {
  const u = String((body && body.user) || ''), p = String((body && body.pass) || '');
  if (u !== 'xx1031' || !p) return null;
  let full = '', ro = '';
  try { full = cleanKV(await POOL.get('CONSOLE_PASS')); } catch (e) {}
  try { ro = cleanKV(await POOL.get('CONSOLE_RO_PASS')); } catch (e) {}
  // 满权限口令优先判：万一两把口令被设成同一个值，登进来的应该是满权限那档
  if (full && p === full) return 'full';
  if (ro && p === ro) return 'ro';
  return null;
}
async function consoleAuth(body) {
  return !!(await consoleRole(body));
}
// 写接口专用：只认满权限口令
async function consoleAuthFull(body) {
  return (await consoleRole(body)) === 'full';
}
// ---- 2026-10-23：两仓库最近一次 run.yml 作业状态（供控制台「运行状态」横条）----
// 以前「今晚 38/38 到底成没成」只能人工去 GitHub 翻，job 绿但分片静默失败也看不出来。
// 拉概览 + job 明细数成功数；结果写 KV 缓存 5 分钟（GitHub token 限 5000 次/小时，
// 控制台刷新一次 = 双仓库×2 请求，不缓存几分钟就能烧掉小半额度）。
// dz 仓库名与 PEER_DEFAULT 同理属于「运行所需常量」写死；GH_TOKEN 未配置时返回空数组，页面显示「未配置」。
async function fetchActionsStatus() {
  const c = await cfg();
  if (!c.ghToken) return [];
  try {
    const hit = await POOL.get('actions:cache');
    if (hit) { const arr = JSON.parse(hit); if (Array.isArray(arr)) return arr; }
  } catch (e) { /* 缓存读失败按没有处理 */ }
  const repos = [
    { pool: 'hz', owner: c.owner, repo: c.repo },
    { pool: 'dz', owner: 'xm921017', repo: 'dingzhi' },
  ];
  const out = await Promise.all(repos.map(async (r) => {
    try {
      const base = 'https://api.github.com/repos/' + r.owner + '/' + r.repo;
      const H = { Authorization: 'Bearer ' + c.ghToken, Accept: 'application/vnd.github+json',
                  'User-Agent': 'cron-relay-worker' };
      const T = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 6000))]);
      const rr = await T(fetch(base + '/actions/workflows/run.yml/runs?per_page=1&status=completed', { headers: H }));
      if (!rr.ok) throw new Error('runs http ' + rr.status);
      const rd = await rr.json();
      const run = (rd.workflow_runs || [])[0];
      if (!run) return { pool: r.pool, ok: false, note: '无运行记录' };
      let jobsOk = 0, jobsTotal = 0;
      try {
        const jr = await T(fetch(base + '/actions/runs/' + run.id + '/jobs?per_page=100', { headers: H }));
        if (jr.ok) {
          const jd = await jr.json();
          jobsTotal = (jd.jobs || []).length;
          jobsOk = (jd.jobs || []).filter(j => j.conclusion === 'success').length;
        }
      } catch (e) { /* job 明细拉失败不影响概览展示 */ }
      return { pool: r.pool, ok: true, conclusion: run.conclusion || '', created: run.created_at || '',
               run_id: run.id, jobs_ok: jobsOk, jobs_total: jobsTotal, url: run.html_url || '' };
    } catch (e) {
      return { pool: r.pool, ok: false, note: String((e && e.message) || e).slice(0, 60) };
    }
  }));
  try { await POOL.put('actions:cache', JSON.stringify(out), { expirationTtl: 300 }); } catch (e) { /* 缓存写失败不致命 */ }
  return out;
}
// ---- 2026-10-24：Cloudflare Cron 定时触发 snap650（GitHub schedule 靠不住）----
// 背景：snap650 用 GitHub 的 schedule（北京 10:00）上线两天 0 次自动运行；同期 relay 计划 22:23
// 实际 02:25 才跑、coverage 计划 20:00 实际 00:43 才跑 —— GitHub 免费档的 schedule 在高负载时
// 会整体推迟数小时甚至丢弃。650 是「日环比」型数据，晚几小时整天判断都失真，必须准点。
// 方案：CF 原生 cron（几乎准点，见 CF 侧 schedules 配置）→ GitHub workflow_dispatch 触发 snap650；
// GitHub 侧 schedule 保留一份晚 2 小时的兜底。两边跑同一个 workflow，重复采集由快照写入的
// 「同号同天 rpc30 大者胜」自然去重，不会写坏数据。
const SNAP650_REPOS = [
  // 两个仓库分属两个 GitHub 账号，PAT 的 admin 权限不通用（实测 xm921018 的 PAT 对 dingzhi
  // 只有 pull 权限，dispatch 直接 403 "Must have admin rights to Repository"），故分开配钥匙：
  // hz 用既有 GH_TOKEN（xm921018，KV 里早已存在），dz 用 GH_TOKEN_DZ（xm921017，2026-10-24 新增）。
  { pool: 'hz', owner: 'xm921018', repo: 'cron-relay', tokenKey: 'GH_TOKEN' },
  { pool: 'dz', owner: 'xm921017', repo: 'dingzhi', tokenKey: 'GH_TOKEN_DZ' },
];
async function dispatchSnap650(onlyPool) {
  const c = await cfg();
  const jobs = SNAP650_REPOS.filter(r => !onlyPool || onlyPool === 'all' || r.pool === onlyPool);
  const out = [];
  for (const r of jobs) {
    let tok = c.ghToken;
    if (r.tokenKey !== 'GH_TOKEN') {
      tok = cleanKV(await POOL.get(r.tokenKey).catch(() => null)) || '';
      if (!tok) {
        out.push({ pool: r.pool, status: 0, ok: false,
                   message: 'KV 缺少 ' + r.tokenKey + '（该仓库属于另一个 GitHub 账号，需要单独配 PAT）' });
        continue;
      }
    }
    if (!tok) {
      out.push({ pool: r.pool, status: 0, ok: false, message: 'KV 里没有 ' + r.tokenKey });
      continue;
    }
    try {
      const resp = await fetch('https://api.github.com/repos/' + r.owner + '/' + r.repo +
        '/actions/workflows/snapshot.yml/dispatches', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json',
                   'User-Agent': 'cron-relay-worker', 'Content-Type': 'application/json' },
        body: JSON.stringify({ ref: 'main' }),
      });
      // workflow_dispatch 成功返回 204 且 body 为空
      out.push({ pool: r.pool, status: resp.status, ok: resp.status === 204,
                 message: resp.ok ? '' : (await resp.text()).slice(0, 120) });
    } catch (e) {
      out.push({ pool: r.pool, status: 0, ok: false, message: String((e && e.message) || e).slice(0, 120) });
    }
  }
  // 只留最后一次触发记录（1 周过期），控制台/排障时可直接查它到底有没有被调起来
  try {
    await POOL.put('cron:snap650:last', JSON.stringify({ at: new Date().toISOString(), out }),
                   { expirationTtl: 604800 });
  } catch (e) { /* 记录失败不影响触发本身 */ }
  return { ok: out.every(x => x.ok), jobs: out };
}
// ---- 读一天的快照：聚合 snap:<date>:<pool>:<分片> 所有键 → { hz: {uid: acc}, dz: {uid: acc} } ----
async function readSnapDay(date) {
  const out = { hz: {}, dz: {} };
  // 2026-10-22：快照改读 D1 snapshots 表。原来是 list 一次 + 每个分片一次 get，
  // 且 list 走 KV 配额；现在一条 SELECT 就拿到当天全部号。
  if (d1ok()) {
    const rows = await d1All('SELECT pool,uid,rate,rpc30,cnt,missions,dur,at FROM snapshots WHERE day=?', [date]);
    if (rows) {
      for (const r of rows) {
        const pool = r.pool === 'dz' ? 'dz' : 'hz';
        let mis = {};
        try { mis = r.missions ? JSON.parse(r.missions) : {}; } catch (e) {}
        // 2026-10-23：acc 增加 at（快照写入时间），供控制台「今进度」单元格显示采集时间，
        // 避免把凌晨边跑边采的旧值当成当前真实进度。KV 回退路径的 acc 没有 at，页面判空不显示。
        const acc = { rate: r.rate == null ? null : Number(r.rate), rpc30: r.rpc30 == null ? null : Number(r.rpc30),
                      cnt: r.cnt == null ? null : Number(r.cnt), mis: mis || {},
                      dur: r.dur == null ? null : Number(r.dur), at: r.at || '' };
        const prev = out[pool][r.uid];
        // 同号同天多次写入时，保留 rpc30 更大（更新）的那份
        if (!prev || ((acc.rpc30 || 0) >= (prev.rpc30 || 0))) out[pool][r.uid] = acc;
      }
      return out;
    }
  }
  // ---- KV 回退路径 ----
  try {
    let cursor;
    do {
      const page = await POOL.list({ prefix: 'snap:' + date + ':', cursor: cursor });
      for (const k of (page.keys || [])) {
        const parts = k.name.split(':');
        const pool = parts[2] === 'dz' ? 'dz' : 'hz';
        let v;
        try { v = JSON.parse(await POOL.get(k.name)); } catch (e) { continue; }
        if (!v || !v.accs) continue;
        for (const [uid, acc] of Object.entries(v.accs)) {
          const prev = out[pool][uid];
          // 同号同天多片写入时，保留 rpc30 更大（更新）的那份
          if (!prev || ((acc.rpc30 || 0) >= (prev.rpc30 || 0))) out[pool][uid] = acc;
        }
      }
      cursor = page.list_complete ? null : page.cursor;
    } while (cursor);
  } catch (e) { /* 列表失败按空快照处理 */ }
  return out;
}
// ---- 北京日期减一天 ----
function dateMinus1(dateStr) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr || '');
  if (!m) return dateStr;
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  d.setUTCDate(d.getUTCDate() - 1);
  return d.toISOString().slice(0, 10);
}
// ---- 北京日期减 N 天（N>=1；非法输入原样返回）----
function dateMinusN(dateStr, n) {
  let d = dateStr;
  for (let i = 0; i < (n || 0); i++) d = dateMinus1(d);
  return d;
}
// ---- 连续不涨天数（2026-10-23 控制台新增，纯计算无副作用）----
// 输入：最近 N 天 snapshots 行（day,pool,uid,rate）。
// 口径：按 (池,号,天) 取最大 rate（650 进度单调增，同一天多份写入取最新进度）；
//       跳过无快照的天（数据断层不冤枉号）；从最新一天往前数连续 rate<=前一天 的天数；
//       只有 >=2 的才收录（1 天不涨日环比列本身可见，避免满屏标记）。
// 输出：{ hz:{uid:n}, dz:{uid:n} }
function calcStreaks(rows) {
  const byKey = {};
  for (const r of (rows || [])) {
    if (!r || r.rate == null) continue;
    const pool = r.pool === 'dz' ? 'dz' : 'hz';
    const k = pool + '|' + String(r.uid);
    const day = String(r.day);
    const v = Number(r.rate) || 0;
    const m = byKey[k] || (byKey[k] = {});
    if (m[day] == null || v > m[day]) m[day] = v;
  }
  const out = { hz: {}, dz: {} };
  for (const k of Object.keys(byKey)) {
    const days = Object.keys(byKey[k]).sort();
    if (days.length < 2) continue;
    let streak = 0;
    for (let i = days.length - 1; i > 0; i--) {
      if (byKey[k][days[i]] <= byKey[k][days[i - 1]]) streak++;
      else break;
    }
    if (streak >= 2) {
      const pool = k.slice(0, k.indexOf('|'));
      out[pool][k.slice(k.indexOf('|') + 1)] = streak;
    }
  }
  return out;
}

// ---- 账号编辑共用逻辑（2026-10-22 从 /api/admin/entry 抽出，行为与原实现逐行一致）----
// 供 /api/admin/entry（管理密码）与 /api/console/entry（控制台登录）两个路由调用。
async function applyEntryEdit(body) {
  const CORS = { 'Access-Control-Allow-Origin': '*' };
  const master = await mergePool();
  const target = master.find(e =>
    (body.uid != null && String(body.uid) !== '' && e.uid != null && String(e.uid) === String(body.uid)) ||
    (body.name && String(e.name) === String(body.name)));
  if (!target) return json({ message: '没找到该账号（可能已被删除）' }, 404, CORS);
  if (body.action === 'delete') {
    await POOL.delete(entryKeyOf(target));
    try { await d1Delete(target); } catch (e) { console.error('D1 删除镜像失败:', e && e.message); }
    try {
      const log = new Set(await getDeadLog());
      log.add(entryKeyOf(target));
      await POOL.put('dead_log', JSON.stringify([...log].slice(-500)));
    } catch (e) {}
    const kept = master.filter(e => e !== target);
    await d1LogDead([target], 'manual');
    // 2026-10-26：同时进「通知号主」判定队列（12 小时后判是不是真删，见 /api/dead_pending）。
    // 这里是纯新增的一行写入，不影响任何既有行为；写失败也只是少一封邮件。
    try { await d1QueueNotice(target); } catch (e) { console.error('通知队列写入失败:', e && e.message); }
    // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
    await pushPool(kept);
    try { await refreshPoolSnap(); } catch (e) {}
    return json({ ok: true, message: '已删除账号 ' + (target.name || target.uid) }, 200, CORS);
  }
  if (body.action === 'update') {
    const changes = [];
    if (body.ck != null && String(body.ck).trim() !== '') {
      let mu = String(body.ck).trim();
      const mm = mu.match(/MUSIC_U=([^;\s"']+)/);
      if (mm) mu = mm[1];
      if (!/^[A-Za-z0-9%_-]{20,}$/.test(mu)) return json({ message: 'MUSIC_U 格式不对（应为 32 位左右的长字符串）' }, 400, CORS);
      const v = await validateCookie(mu);
      if (!v.ok) return json({ message: '新 CK 校验未通过：' + v.msg }, 400, CORS);
      target.ck = 'MUSIC_U=' + mu;
      changes.push('CK');
    }
    if (body.link != null && String(body.link).trim() !== '') {
      const song = await resolveSong(String(body.link));
      if (!song.ok) return json({ message: song.msg }, 400, CORS);
      target.song = song.song;
      changes.push('歌曲');
    }
    if (body.email != null && String(body.email).trim() !== '') {
      const em = String(body.email).trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return json({ message: '邮箱格式不对' }, 400, CORS);
      target.email = em;
      changes.push('邮箱');
    }
    if (body.exp != null && String(body.exp).trim() !== '') {
      const x = String(body.exp).trim();
      if (x === 'forever' || x === '永久') { delete target.exp; changes.push('有效期=永久'); }
      else if (/^\d{4}-\d{2}-\d{2}$/.test(x)) { target.exp = x; changes.push('有效期=' + x); }
      else if (/^\d{1,4}$/.test(x)) { const d = beijingDatePlus(parseInt(x, 10)); target.exp = d; changes.push('有效期=' + x + '天(' + d + '止)'); }
      else return json({ message: '有效期格式不对：填天数(如30)、日期(2026-12-31)或"永久"' }, 400, CORS);
    }
    if (body.noListen !== undefined && body.noListen !== null) {
      target.noListen = !!body.noListen;
      changes.push(body.noListen ? '暂停互听(只收不听)' : '恢复互听');
    }
    // 2026-10-27：客服标签 / 套餐档位（补录、纠错用）。留空=不改，与其它栏口径一致。
    // 注意：改套餐不会自动改有效期（两件事分开），要一起改就把「有效期」也填上。
    if (body.agent != null && String(body.agent).trim() !== '') {
      target.agent = normAgent(body.agent);
      changes.push('客服=' + (target.agent || '未标注'));
    }
    if (body.plan != null && String(body.plan).trim() !== '') {
      const rcE = await regCfg();
      const plE = planOf(rcE, body.plan);
      target.plan = plE ? plE.label : normAgent(body.plan).slice(0, 8);
      changes.push('套餐=' + target.plan);
    }
    if (!changes.length) return json({ message: '没有要修改的内容（各栏留空=不改）' }, 400, CORS);
    await POOL.put(entryKeyOf(target), JSON.stringify(target));
    // 2026-10-22：D1 已是唯一读路径，镜像写失败必须显式告诉调用方 ——
    // 否则界面显示"已修改"，第二天读 D1 又变回旧值，谁都不知道出了事。
    let d1okEdit = false;
    try { d1okEdit = await d1Upsert(target); } catch (e) { console.error('D1 修改镜像失败:', e && e.message); }
    // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
    await pushPool(master);
    try { await refreshPoolSnap(); } catch (e) {}
    return json({ ok: true, d1: !!d1okEdit,
      message: '已修改 ' + (target.name || target.uid) + '：' + changes.join('、')
        + (d1okEdit ? '' : '（⚠️ D1 镜像写入失败：KV 已保存，请稍后调 /api/resync 补齐）') }, 200, CORS);
  }
  return json({ message: '未知操作' }, 400, CORS);
}

const GATE_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>请输入访问口令</title><style>body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}.box{background:#fff;border-radius:14px;padding:28px 24px;width:320px;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}h1{font-size:17px;font-weight:600;color:#3b6d11;margin:0 0 6px}p{font-size:13px;color:#666;margin:0 0 18px;line-height:1.6}input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #ddd;border-radius:8px;font-size:15px;text-align:center;letter-spacing:2px}button{margin-top:12px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:15px;cursor:pointer}</style></head><body><form class="box" method="get" action=""><h1>成员接入</h1><p>请输入访问口令后继续</p><input name="k" type="password" placeholder="访问口令" autofocus autocomplete="off"><button type="submit">进入</button></form></body></html>`;
const INDEX_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>成员接入</title><style>body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;padding:24px 12px;display:flex;flex-direction:column;align-items:center;gap:16px}.head{text-align:center;margin-bottom:2px}.page-title{font-size:20px;font-weight:600;color:#3b6d11;margin:0}.page-sub{font-size:13px;color:#666;margin:6px 0 0}.wrap{display:flex;flex-wrap:wrap;gap:18px;justify-content:center;width:100%;max-width:1060px}.card{background:#fff;padding:26px 22px;border-radius:14px;width:330px;min-width:0;box-sizing:border-box;box-shadow:0 2px 12px rgba(0,0,0,.08)}h1{font-size:17px;margin:0 0 4px}h1.alt{color:#b06a00}p{font-size:13px;color:#666;margin:0 0 16px;line-height:1.5}label{display:block;font-size:13px;margin:12px 0 4px;color:#333}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ddd;border-radius:8px;font-size:14px}.row{display:flex;gap:8px}.row input{flex:1}button{margin-top:14px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:15px;cursor:pointer}button.mini{margin-top:0;width:auto;padding:10px 12px;font-size:13px;background:#5a8f1d;white-space:nowrap}button:disabled{opacity:.55;cursor:default}.msg{margin-top:14px;font-size:13px;min-height:18px;line-height:1.5}.ok{color:#3b6d11}.err{color:#a32d2d}.tip{color:#666}details{margin-top:14px;font-size:12px;color:#666;line-height:1.6}summary{cursor:pointer;color:#3b6d11}code{background:#eee;padding:1px 4px;border-radius:4px}.admin-entry{margin:10px 0 0;font-size:12px}.admin-entry a{color:#3b6d11;text-decoration:none;border-bottom:1px dashed #3b6d11;padding-bottom:1px}.abox{background:#fff;padding:22px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:1060px;box-sizing:border-box}.stats{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px}.stat{flex:1;min-width:100px;background:#f2f7ea;border-radius:10px;padding:10px 12px;text-align:center}.stat b{display:block;font-size:20px;color:#3b6d11}.stat span{font-size:12px;color:#666}.stat.warn b{color:#b06a00}.stat.warn{background:#fdf3e3}.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}.tools input{flex:1;min-width:160px;padding:9px 10px;border:1px solid #ddd;border-radius:8px;font-size:14px}.tools button{margin-top:0;width:auto;padding:9px 14px;font-size:13px}button.gray{background:#888}.twrap{overflow-x:auto;border:1px solid #eee;border-radius:10px}table{border-collapse:collapse;width:100%;font-size:13px}th{background:#f5f6f8;text-align:left;padding:9px 10px;white-space:nowrap;color:#444;border-bottom:1px solid #eee}td{padding:8px 10px;border-bottom:1px solid #f2f2f2;white-space:nowrap}tr:hover td{background:#fafdf5}.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:8px;margin-right:4px}.b-red{background:#fbe4e4;color:#a32d2d}.b-gray{background:#eee;color:#666}.b-yellow{background:#fdf3e3;color:#b06a00}.num{font-family:ui-monospace,Consolas,monospace;color:#555}</style></head><body><div class="head"><h1 class="page-title">成员接入</h1><p class="page-sub">在下方登记新账号；已经登记过的成员，可在下方补录或修改通知邮箱（页面版本 v20261028a）</p></div><div class="wrap"><div class="card"><h1>成员接入（复制 MUSIC_U）</h1><p>自己从浏览器复制 <code>MUSIC_U</code> 粘贴过来，<b>次日生效</b>。注意：<b>每个账号限登记一首歌</b>，重复登记会被拒绝；<b>号池上限 __POOL_LIMIT__ 人</b>，满员后暂停登记。</p><label>MUSIC_U</label><input id="mu" placeholder="粘贴浏览器里的 MUSIC_U 值"><label>分享链接</label><input id="link2" placeholder="粘贴 APP 内分享的单曲链接"><label>邮箱（必填）</label><input id="email2" type="text" placeholder="账号有变化时邮件通知你"><button id="btn2">直接登记</button><details><summary>怎么拿到 MUSIC_U？（点开看）</summary>用电脑浏览器打开 <code>https://music.163.com</code> 并登录 → 按 <code>F12</code> → 切到「Application / 应用」标签 → 左侧展开 <code>Cookies</code> → 选 <code>music.163.com</code> → 在右边找到名为 <code>MUSIC_U</code> 的那一行，复制它的「Value / 值」整串粘进来即可。</details><div class="msg tip" id="msg2"></div></div><div class="card"><h1 class="alt">绑定 / 更换通知邮箱</h1><p>之前登记时没填邮箱、或者想换一个邮箱，在这里改一下就行。<b>只改邮箱，其他设置原样不动</b>，之后想再换随时能来改。账号有变化时（比如需要完成一次验证、登录过期），会发邮件到这个邮箱提醒你。</p><label>手机号（用手机号登记过的填这个）</label><input id="pm_phone" inputmode="numeric" maxlength="11" placeholder="登记时用的 11 位手机号"><label>MUSIC_U（复制 MUSIC_U 登记的填这个，与手机号二选一即可）</label><input id="pm_mu" placeholder="登记时粘贴的 MUSIC_U"><label>常用邮箱</label><input id="pm_email" type="text" placeholder="name@qq.com"><button id="btn3">保存邮箱</button><div class="msg tip" id="msg3">手机号和 MUSIC_U 填其中一个就行。</div></div></div><script>const $=id=>document.getElementById(id);function normPhone(s){return (s||'').replace(/[０-９]/g,c=>String.fromCharCode(c.charCodeAt(0)-65248)).replace(/[^0-9]/g,'');}function setMsg(el,t,cls){const m=$(el);m.textContent=t;m.className='msg'+(cls?(' '+cls):'');}$('btn2').onclick=async()=>{const musicU=$('mu').value.trim(),link=$('link2').value.trim(),email=$('email2').value.trim();if(!musicU){setMsg('msg2','请填写 MUSIC_U','err');return;}if(!email){setMsg('msg2','请填写邮箱（用于接收任务验证码与异常提醒）','err');return;}if(!link){setMsg('msg2','请填写歌曲链接','err');return;}setMsg('msg2','处理中…');$('btn2').disabled=true;try{const r=await fetch('/api/join_manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({musicU,link,email})});const d=await r.json();if(r.ok){setMsg('msg2',d.message||'登记成功，次日开始。','ok');}else{setMsg('msg2',d.message||'失败','err');}}catch(e){setMsg('msg2','网络错误','err');}$('btn2').disabled=false;};$('btn3').onclick=async()=>{const phone=normPhone($('pm_phone').value),mu=$('pm_mu').value.trim(),email=$('pm_email').value.trim();if(!phone&&!mu){setMsg('msg3','手机号和 MUSIC_U 至少填一个','err');return;}if(!email){setMsg('msg3','请填写常用邮箱','err');return;}setMsg('msg3','正在保存…');$('btn3').disabled=true;try{const r=await fetch('/api/updatemail',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone,mu,email})});const d=await r.json();if(r.ok){setMsg('msg3',d.message||'已保存','ok');}else{setMsg('msg3',d.message||'保存失败','err');}}catch(e){setMsg('msg3','网络错误','err');}$('btn3').disabled=false;};</script></body></html>`;
// 二群已拆分为独立系统（dingzhi worker / dingzhi 仓库 / POOL-DZ 独立 KV 号池），
// 主 worker 只服务一群；原 /g2 路由与二群页面已下线（2026-10-18）。

const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>号池管理后台</title>
<style>
body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;padding:24px 12px;display:flex;flex-direction:column;align-items:center;gap:16px}
.head{text-align:center}.page-title{font-size:20px;font-weight:600;color:#3b6d11;margin:0}
.page-sub{font-size:13px;color:#666;margin:6px 0 0}
.abox{background:#fff;padding:22px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:1060px;box-sizing:border-box}
h2{font-size:16px;margin:0 0 4px}
.tip{font-size:12px;color:#999;margin:0 0 14px}
input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ddd;border-radius:8px;font-size:14px}
button{margin-top:12px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:15px;cursor:pointer}
button.gray{background:#999}
button.mini{margin-top:0;width:auto;padding:9px 14px;font-size:13px}
button:disabled{opacity:.55;cursor:default}
.msg{margin-top:12px;font-size:13px;min-height:18px}
.ok{color:#3b6d11}.err{color:#a32d2d}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px}
.stat{flex:1;min-width:104px;background:#f2f7ea;border-radius:10px;padding:10px 12px;text-align:center}
.stat b{display:block;font-size:20px;color:#3b6d11}
.stat span{font-size:12px;color:#666}
.stat.warn{background:#fdf3e3}.stat.warn b{color:#b06a00}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.tools input{flex:1;min-width:160px}
.twrap{overflow-x:auto;border:1px solid #eee;border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{background:#f5f6f8;text-align:left;padding:9px 10px;white-space:nowrap;color:#444;border-bottom:1px solid #eee}
td{padding:8px 10px;border-bottom:1px solid #f2f2f2;white-space:nowrap}
tr:hover td{background:#fafdf5}
.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:8px;margin-right:4px}
.b-red{background:#fbe4e4;color:#a32d2d}.b-gray{background:#eee;color:#666}.b-yellow{background:#fdf3e3;color:#b06a00}
.num{font-family:ui-monospace,Consolas,monospace;color:#555}
a.song{color:#3b6d11;text-decoration:none;border-bottom:1px dotted #3b6d11}
</style>
</head>
<body>
<div class="head"><h1 class="page-title">互听群号池管理后台</h1><p class="page-sub">仅群主可访问，页面不显示登录凭证</p></div>

<div class="abox" id="loginBox">
  <h2>管理密码</h2>
  <p class="tip">输入后浏览器会本地记住，过期可点"退出登录"清除。</p>
  <input id="pw" type="password" placeholder="管理密码（ADMIN_PASS）">
  <button id="btn">进入后台</button>
  <div class="msg" id="lm"></div>
</div>

<div class="abox" id="mainBox" hidden>
  <div class="stats" id="stats"></div>
  <div class="tools">
    <input id="q" placeholder="搜索：账号 / 邮箱 / UID / 歌曲ID">
    <button class="mini" id="btnCsv">导出 CSV</button>
    <button class="mini" id="btnCopy">复制未绑邮箱名单</button>
    <button class="mini" id="btnRefresh">刷新</button>
    <button class="mini gray" id="btnOut">退出登录</button>
  </div>
  <div class="twrap">
    <table>
      <thead><tr><th>#</th><th>账号</th><th>UID</th><th>绑定歌曲</th><th>入池日期</th><th>通知邮箱</th><th>标记</th></tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>
  <p class="tip" style="margin:12px 0 0">改绑歌曲 / 删除账号 / 换 CK 等写操作请在本地跑「号池管理.bat」，本后台只读，防止误操作。</p>
</div>

<script>
var POOL=[],STATS={};
function $(id){return document.getElementById(id);}
function msg(t,ok){var m=$('lm');m.textContent=t;m.className='msg'+(ok?' ok':' err');}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function login(){
  var p=$('pw').value.trim();
  if(!p){msg('请输入管理密码');return;}
  $('btn').disabled=true;
  fetch('/api/pool',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pass:p})})
  .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
  .then(function(o){
    $('btn').disabled=false;
    if(!o.ok){msg(o.d.message||'管理密码错误');return;}
    try{localStorage.setItem('poolAdminPass',p);}catch(e){}
    POOL=o.d.entries||[];STATS=o.d.stats||{};
    $('loginBox').hidden=true;$('mainBox').hidden=false;
    render();
  }).catch(function(){ $('btn').disabled=false; msg('网络错误，请重试'); });
}
$('btn').onclick=login;
$('pw').onkeydown=function(e){if(e.key==='Enter')login();};
$('btnOut').onclick=function(){try{localStorage.removeItem('poolAdminPass');}catch(e){}location.reload();};
$('btnRefresh').onclick=function(){fetchPool();};
$('q').oninput=render;
$('btnCopy').onclick=function(){
  var noMail=POOL.filter(function(e){return !e.email;});
  if(!noMail.length){alert('全部已绑定邮箱');return;}
  var txt='请以下成员到登记页绑定通知邮箱（账号异常时邮件通知本人）：\\n'+noMail.map(function(e){return e.name;}).join('\\n');
  function done(){$('btnCopy').textContent='已复制 '+noMail.length+' 条';setTimeout(function(){$('btnCopy').textContent='复制未绑邮箱名单';},2500);}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done,function(){fallback();});}else fallback();
  function fallback(){var ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done();}catch(e){alert('复制失败，请手动选择');}document.body.removeChild(ta);}
};
$('btnCsv').onclick=function(){
  var rows=[['序号','账号','UID','歌曲ID','入池日期','邮箱','互听状态']];
  // 2026-10-26 修复：末列原来是 e.marks，但 /api/pool 从不返回该字段 → 这一列永远是空。
  // 改成导出现有字段里真正有意义的「互听状态」。
  POOL.forEach(function(e,i){rows.push([i+1,e.name,e.uid||'',e.song||'',e.added||'',e.email||'',e.noListen?'只收不听':'正常']);});
  var csv='\ufeff'+rows.map(function(r){return r.map(function(v){return '"'+String(v).replace(/"/g,'""')+'"';}).join(',');}).join('\\r\\n');
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='号池_'+new Date().toISOString().slice(0,10)+'.csv';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
};
function fetchPool(){
  var p='';try{p=localStorage.getItem('poolAdminPass')||'';}catch(e){}
  if(!p){$('loginBox').hidden=false;$('mainBox').hidden=true;return;}
  fetch('/api/pool',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pass:p})})
  .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
  .then(function(o){
    if(!o.ok){msg(o.d.message||'请重新登录');$('loginBox').hidden=false;$('mainBox').hidden=true;return;}
    POOL=o.d.entries||[];STATS=o.d.stats||{};render();
  }).catch(function(){});
}
function badges(e){
  var h='';
  if(e.noListen)h+='<span class="badge b-red">只收</span>';
  if(!e.song)h+='<span class="badge b-gray">公益</span>';
  if(!e.email)h+='<span class="badge b-yellow">无邮箱</span>';
  if(String(e.name).indexOf('manual:')===0)h+='<span class="badge b-gray">手动</span>';
  return h||'<span style="color:#bbb">正常</span>';
}
function render(){
  var q=($('q').value||'').trim().toLowerCase();
  var list=POOL.filter(function(e){
    if(!q)return true;
    return (e.name+' '+(e.email||'')+' '+(e.uid||'')+' '+(e.song||'')).toLowerCase().indexOf(q)>=0;
  });
  $('stats').innerHTML=
    '<div class="stat"><b>'+STATS.total+'</b><span>号池总数</span></div>'
   +'<div class="stat"><b>'+STATS.withMail+'</b><span>已绑邮箱</span></div>'
   +'<div class="stat'+(STATS.noMail?' warn':'')+'"><b>'+STATS.noMail+'</b><span>未绑邮箱</span></div>'
   +'<div class="stat'+(STATS.noListen?' warn':'')+'"><b>'+STATS.noListen+'</b><span>只收号</span></div>'
   +'<div class="stat"><b>'+STATS.public+'</b><span>公益号</span></div>'
   +'<div class="stat"><b>'+(STATS.limit||1200)+'</b><span>人数上限</span></div>'
   +'<div class="stat'+(STATS.remain<=20?' warn':'')+'"><b>'+STATS.remain+'</b><span>剩余名额</span></div>'
   +'<div class="stat"><b>'+(list.length)+'</b><span>当前筛选</span></div>';
  var h='';
  list.forEach(function(e,i){
    var song=e.song?'<a class="song" target="_blank" href="https://music.163.com/song?id='+e.song+'">'+e.song+'</a>':'<span style="color:#bbb">—</span>';
    h+='<tr><td class="num">'+(i+1)+'</td><td>'+esc(String(e.name||'').replace(/^manual:/,'手动·'))+'</td><td class="num">'+esc(e.uid)+'</td><td class="num">'+song+'</td><td class="num">'+esc(e.added)+'</td><td>'+esc(e.email||'—')+'</td><td>'+badges(e)+'</td></tr>';
  });
  $('tb').innerHTML=h||'<tr><td colspan="7" style="text-align:center;color:#999;padding:20px">没有匹配的账号</td></tr>';
}
try{
  var _pw=null;
  try{var _h=(location.hash||'').match(/(?:^#|[#&])pw=([^&]*)/)||(location.search||'').match(/[?&]pw=([^&]*)/);if(_h)_pw=decodeURIComponent(_h[1]);}catch(e){}
  if(_pw){try{history.replaceState(null,'',location.pathname);}catch(e1){};var _el=$('pw');if(_el)_el.value=_pw;login();}
  else if(localStorage.getItem('poolAdminPass')) fetchPool();
}catch(e){}
</script>
</body>
</html>`;


// ---- 进阶控制台页面（2026-10-22）：两池账号每日快照 + 日环比 + 编辑。登录账号/密码均 xx1031（CONSOLE_PASS 可覆盖密码）----
const CONSOLE_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>650任务进阶控制台</title><style>
body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;padding:20px 12px}
.head{text-align:center;margin-bottom:10px}.page-title{font-size:19px;font-weight:600;color:#3b6d11;margin:0}.page-sub{font-size:12px;color:#888;margin:5px 0 0}
.abox{background:#fff;padding:20px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:1800px;box-sizing:border-box;margin:0 auto 14px}
#loginBox{max-width:520px}
input,select{padding:9px 10px;border:1px solid #ddd;border-radius:8px;font-size:13px;box-sizing:border-box}
button{padding:9px 14px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:13px;cursor:pointer}
button.gray{background:#888}button.warn{background:#a32d2d}button:disabled{opacity:.55;cursor:default}
.msg{font-size:13px;min-height:16px;margin-top:8px}.ok{color:#3b6d11}.err{color:#a32d2d}
.stats{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.stat{flex:1;min-width:96px;background:#f2f7ea;border-radius:10px;padding:8px 10px;text-align:center}
.stat b{display:block;font-size:19px;color:#3b6d11}.stat span{font-size:11px;color:#666}
.stat.warn{background:#fdf3e3}.stat.warn b{color:#b06a00}
/* 2026-10-27 新增：套餐汇总条（按「登记时买的套餐」统计，跟着客服/套餐筛选一起变） */
.plans{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.pl{background:#fff;border:1px solid #e8eaee;border-radius:9px;padding:6px 12px;font-size:12px;color:#555}
.pl b{font-size:15px;color:#3b6d11;margin-left:5px}
.pl.muted{color:#9aa5b1}.pl.muted b{color:#aab4c0}
.ro{display:inline-block;background:#fdf3e3;color:#b06a00;border-radius:8px;padding:2px 9px;font-size:11px;margin-left:6px;vertical-align:middle;font-weight:400}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.tools input{min-width:130px}.tools input#q{flex:1;min-width:160px}
/* 2026-10-27 二次改（用户要求）：不要单独的「入池范围」控件，
   就在原来那个单日期后面再放一个日期，两个框连起来当一个日期范围用。 */
.dr{display:inline-flex;align-items:center;gap:3px;background:#f5f6f8;border:1px solid #e8eaee;border-radius:8px;padding:2px 6px}
.dr em{font-style:normal;color:#aab4c0;font-size:12px}
.dr input{border:1px solid #ddd;border-radius:6px;padding:5px 6px;font-size:12.5px;min-width:118px;background:#fff}
.dr .dn{font-style:normal;font-size:11.5px;color:#3b6d11;font-weight:700;padding:0 2px;display:none}
.dr .dx{cursor:pointer;color:#999;font-size:15px;padding:0 4px;line-height:1;user-select:none;display:none}
.dr .dx:hover{color:#a32d2d}
.dr.on{background:#f2f7ea;border-color:#cfe0b4}
.dr.on .dn,.dr.on .dx{display:inline}
.tab{padding:8px 14px;border-radius:8px;background:#eee;color:#555;cursor:pointer;font-size:13px}
.tab.on{background:#3b6d11;color:#fff}
.twrap{overflow:auto;max-height:calc(100vh - 170px);border:1px solid #eee;border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:12.5px;white-space:nowrap}
th{background:#f5f6f8;text-align:left;padding:8px 9px;color:#444;border-bottom:1px solid #eee}
.twrap th{position:sticky;top:0;z-index:3;box-shadow:inset 0 -1px 0 #eee,0 1px 4px rgba(0,0,0,.05)}
td{padding:7px 9px;border-bottom:1px solid #f2f2f2}
tr:hover td{background:#fafdf5}
.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:8px;margin-right:3px}
.b-hz{background:#e8f2df;color:#3b6d11}.b-dz{background:#e3ecf7;color:#2d5aa3}
.b-red{background:#fbe4e4;color:#a32d2d}.b-gray{background:#eee;color:#666}.b-yellow{background:#fdf3e3;color:#b06a00}
.b-orange{background:#fdeee0;color:#b85c00}
/* 2026-10-25 售后标签新增两色：绿=已完成不用管，蓝=刚入池正常等待 */
.b-green{background:#e3f4e3;color:#1e7a1e}.b-blue{background:#e3effa;color:#255ea6}
.snap-at{font-size:10px;color:#aaa;font-weight:400;margin-top:1px;line-height:1.2}
.num{font-family:ui-monospace,Consolas,monospace;color:#555}
a.song{color:#3b6d11;text-decoration:none;border-bottom:1px dotted #3b6d11}
.up{color:#c0392b;font-weight:600}.down{color:#1e8449;font-weight:600}.flat{color:#999}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.35);display:flex;align-items:center;justify-content:center;z-index:9}
.modal[hidden]{display:none}
.mbox{background:#fff;border-radius:14px;padding:22px;width:420px;max-width:94vw;max-height:88vh;overflow:auto}
.mbox h3{margin:0 0 4px;font-size:16px}.mbox label{display:block;font-size:12px;color:#555;margin:10px 0 3px}
.mbox input,.mbox select{width:100%}
.row2{display:flex;gap:8px;margin-top:14px}.row2 button{flex:1}
.mission{font-size:11px;color:#666;max-width:180px;overflow:hidden;text-overflow:ellipsis}
.mtag{display:inline-block;font-size:11px;background:#f1f2f4;color:#666;border-radius:6px;padding:1px 6px;margin-right:3px;white-space:nowrap}
.mtag i{font-style:normal;color:#999}
.lgd{font-size:12px;color:#555;line-height:1.85}
.lgd b{color:#333}
.lgd code{background:#f4f4f6;border-radius:4px;padding:1px 5px;font-size:11px;color:#a33}
.lgd table{white-space:normal;margin:6px 0 2px}
.lgd td,.lgd th{vertical-align:top;padding:5px 8px;font-size:12px}
.lgd .badge{white-space:nowrap}
.runbar{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.rb{flex:1;min-width:170px;background:#fff;border:1px solid #e6e6e6;border-radius:10px;padding:8px 12px;font-size:12px;color:#555;line-height:1.5}
.rb b{font-size:12.5px;color:#333}
.rb .good{color:#3b6d11;font-weight:600}.rb .bad{color:#a32d2d;font-weight:600}.rb .muted{color:#999}
.rb a{color:#3b6d11}
.deadbox{margin:10px 0 0;font-size:12px;color:#555}
.deadbox summary{cursor:pointer;color:#3b6d11;padding:4px 0}
.deadbox table{margin-top:6px;border:1px solid #eee;border-radius:8px}
/* 手机端（<=860px）把 17 列表格改成卡片流。纯 CSS、零 JS 改动 —— 判定口径与桌面端完全同一份，
   只是换了个呈现方式；桌面端（>860px）一行都不受影响。列名读 td 的 data-l（见 render），
   这里只排显示顺序，顺序同 thead：
   1# 2池 3账号 4客服 5UID 6歌曲 7时长 8昨日650 9今日650 10较昨日 11近30日播放 12其他任务
   13入池 14有效期 15套餐 16标记 17操作 */
@media (max-width:860px){
  body{padding:10px 8px}
  .head{margin-bottom:8px}.page-title{font-size:16px}.page-sub{font-size:11px;line-height:1.5}
  .abox{padding:12px;border-radius:12px;margin-bottom:10px}
  #loginBox{max-width:100%}
  .stats{gap:6px;margin-bottom:10px}
  .stat{flex:1 1 30%;min-width:0;padding:7px 5px;border-radius:9px}
  .stat b{font-size:16px}.stat span{font-size:10.5px;line-height:1.25}
  .plans{gap:6px;margin-bottom:10px}
  .pl{flex:1 1 40%;padding:5px 9px;font-size:11.5px}
  .pl b{font-size:14px}
  .tools{gap:6px;margin-bottom:8px}
  .tools input,.tools select,.tools button,.mini{padding:8px 10px;font-size:12.5px}
  /* 手机端：两个日期框平分一行，否则各自换行会顶掉半屏 */
  .dr{width:100%;flex:1 1 100%;justify-content:space-between;padding:3px 5px}
  .dr input{flex:1;min-width:0;padding:7px 4px;font-size:12px}
  .dr .dn{flex:0 0 auto}
  .runbar{gap:6px;margin-bottom:10px}
  .rb{min-width:0;flex:1 1 100%;padding:7px 10px;font-size:11.5px}
  .twrap{border:0;border-radius:0;max-height:none!important;height:auto!important;overflow:visible;background:transparent}
  .twrap table,.twrap tbody{display:block}
  .twrap thead{display:none}
  .twrap tr{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 10px;background:#fff;
    border:1px solid #e8eaee;border-radius:12px;padding:9px 11px;margin:0 0 9px}
  .twrap td{display:flex;flex-wrap:wrap;align-items:baseline;gap:0 5px;border:0;padding:2px 0;
    white-space:normal;flex:1 1 45%;min-width:0;font-size:12.5px;line-height:1.5}
  .twrap td::before{color:#9aa5b1;font-size:11px;flex:0 0 auto}
  .twrap td .snap-at{flex:0 0 100%}
  .twrap td:nth-child(1){order:0;flex:0 0 auto;font-size:11px;color:#b3bcc6;padding-bottom:0}
  .twrap td:nth-child(2){order:1;flex:0 0 auto}
  .twrap td:nth-child(3){order:2;flex:1 1 auto;font-size:14px;font-weight:600;color:#222;padding-bottom:3px}
  .twrap td:nth-child(4){order:3;flex:0 0 auto}
  .twrap td:nth-child(9){order:4;flex:1 1 45%;font-size:14px}
  .twrap td:nth-child(10){order:5;flex:1 1 45%}
  .twrap td:nth-child(16){order:6;flex:0 0 100%;padding:4px 0 2px}
  .twrap td:nth-child(8){order:7;flex:1 1 45%}
  .twrap td:nth-child(11){order:8;flex:1 1 45%}
  .twrap td:nth-child(7){order:9;flex:1 1 45%}
  .twrap td:nth-child(13){order:10;flex:1 1 45%}
  .twrap td:nth-child(14){order:11;flex:1 1 45%}
  .twrap td:nth-child(15){order:12;flex:1 1 45%}
  .twrap td:nth-child(12){order:13;flex:0 0 100%}
  .twrap td:nth-child(5){order:14;flex:1 1 45%}
  .twrap td:nth-child(6){order:15;flex:0 0 100%}
  .twrap td:nth-child(17){order:20;flex:0 0 100%;padding-top:6px;margin-top:4px;border-top:1px solid #f2f4f6}
  .twrap td:nth-child(17) button{width:100%}
  /* 2026-10-27：列名不再用 nth-child 硬编码，改成读 td 的 data-l 属性。
     原来每加一列都要手工重排 15 条 nth-child，10-26 就因为对不上出过一次排版事故；
     改用 data-l 后只有「显示顺序」还需要 nth-child，标签永远跟着格子走。 */
  .twrap td::before{content:attr(data-l);color:#9aa5b1;font-size:11px;flex:0 0 auto}
  .twrap td:not([data-l])::before{content:none}
  /* 「删号记录」6 列表 / 「标记对照表」3 列表，在 360px 下每列只剩几十 px，会被挤成一字一行。
     手机端改成一条一条的块：删号记录 → 首行 池+UID+账号，下面 原因/通知/时间 各占一行带标签；
     对照表 → 标记一行、意思一行、要怎么处理一行（前缀「意思｜」「处理｜」代替表头）。桌面端不受影响。 */
  #deadList table{display:block;white-space:normal;border:0;font-size:11.5px}
  #deadList thead{display:none}
  #deadList tbody{display:block}
  #deadList tr{display:block;padding:6px 0;border-bottom:1px solid #f2f4f6}
  #deadList td{display:inline-block;padding:0 8px 0 0;border:0;vertical-align:top}
  #deadList td:nth-child(4),#deadList td:nth-child(5),#deadList td:nth-child(6){display:block}
  #deadList td:nth-child(4)::before{content:"原因｜";color:#9aa5b1}
  #deadList td:nth-child(5)::before{content:"通知｜";color:#9aa5b1}
  #deadList td:nth-child(6)::before{content:"时间｜";color:#9aa5b1}
  .lgd{font-size:11.5px}
  .lgd table{display:block;white-space:normal;border:0;margin:4px 0 2px}
  .lgd thead{display:none}
  .lgd tbody,.lgd tr{display:block}
  .lgd tr{padding:6px 0 7px;border-bottom:1px solid #f2f4f6}
  .lgd td{display:block;padding:1px 0;border:0;line-height:1.65}
  .lgd td:nth-child(2)::before{content:"意思｜";color:#9aa5b1;font-size:11px}
  .lgd td:nth-child(3)::before{content:"处理｜";color:#9aa5b1;font-size:11px}
  .lgd td[colspan]{display:block;margin:2px 0 0;padding:4px 8px;border-radius:6px}
}
</style></head><body>
<div class="head"><h1 class="page-title" id="ptitle">650 任务进阶控制台</h1><p class="page-sub">两群账号每日快照 · 数据由 Actions 播放时段顺带采集（T+1 可见）· CK 不在页面展示</p></div>
<div class="abox" id="loginBox">
  <h3 style="margin:0 0 10px">输入控制台口令</h3>
  <p style="margin:0 0 8px;color:#888;font-size:13px;line-height:1.5">账号固定 <b>xx1031</b>，只需填口令。<b>本机不保存口令，每次打开这一页都要重新输入</b>。从「网易云CK助手」或手机 App 点「进阶控制台」进来时，口令由软件带过来，不用在这里再输一遍。</p>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <input id="lu" value="xx1031" readonly title="账号固定 xx1031，不用改" style="width:92px;flex:0 0 92px;background:#f5f5f5;color:#999;text-align:center">
    <input id="lp" type="password" placeholder="控制台口令" style="flex:1;min-width:160px">
    <button id="lbtn">进入</button>
  </div>
  <div class="msg" id="lm"></div>
</div>
<div class="abox" id="mainBox" hidden>
  <div class="runbar" id="runbar"></div>
  <div class="stats" id="stats"></div>
  <div class="plans" id="plans"></div>
  <div class="tools">
    <span class="tab on" data-p="all">全部</span><span class="tab" data-p="hz">主群</span><span class="tab" data-p="dz">定制群</span>
    <select id="fagent" title="按客服筛选（顶部套餐汇总、所有统计都跟着变）"><option value="">客服：全部</option></select>
    <select id="fplan" title="按套餐筛选"><option value="">套餐：全部</option></select>
    <span class="dr" id="dr" title="入池日期范围：只看这段时间登记进池的号。只填一端也行（只填左边=这天及以后，只填右边=这天及以前），两边都空=全部。清空点右边的 ×"><input type="date" id="date" title="入池起始日（含）"><em>~</em><input type="date" id="dateTo" title="入池结束日（含）"><i class="dn" id="dn"></i><span class="dx" id="dClear" title="清除入池日期范围">×</span></span>
    <input id="q" placeholder="搜索：账号 / 邮箱 / UID / 歌曲ID / 客服">
    <select id="sort"><option value="default">排序：默认</option><option value="delta">排序：日涨幅↓</option><option value="rate">排序：今日进度↓</option></select>
    <button class="mini" id="btnCsv">导出CSV</button>
    <button class="mini" id="btnRefresh">刷新</button>
    <button class="mini gray" id="btnCfg" style="display:none">客服名单</button>
    <button class="mini gray" id="btnOut">退出</button>
  </div>
  <div class="twrap"><table><thead><tr>
    <th>#</th><th>池</th><th>账号</th><th title="这条登记是谁录的（客服标签，登记前必须在 APK/EXE 里选）">客服</th><th>UID</th><th>绑定歌曲</th><th>时长</th><th id="thA" title="起始日快照里的 650 任务完成度（近30日有效播放，100%=已达标）">昨日<br>650进度</th><th id="thB" title="结束日快照里的 650 任务完成度（近30日有效播放，100%=已达标）">今日<br>650进度</th><th id="thD" title="结束日650进度 - 起始日650进度；红色=涨，绿色=跌，0=这段时间没动，灰色「周期归零」=换新周期导致的 100→0（不是掉量）">较昨日</th><th title="网易工作台 recentPlayCount30：近30日播放次数（不是有效播放，也不等于650进度）">近30日<br>播放量</th><th title="除 650 播放外的同组小任务（如发布笔记，按 已发x/4 显示：30天内发布图文笔记天数≥4，4/4=已完成）；跟播放/650 无关，不看也不影响">其他<br>任务</th><th>入池</th><th>有效期</th><th title="登记时买的套餐（1年/2年/永久）。顶部「套餐汇总」按这一列统计，不按剩余天数算">套餐</th><th>标记</th><th>操作</th>
  </tr></thead><tbody id="tb"></tbody></table></div>
  <details class="deadbox" id="deadBox" hidden><summary>删号记录 / 待复核账号（最近 12 条，来自 D1 dead_log 与 accounts.suspect_at）</summary>
  <div class="muted" style="margin:6px 0 8px">原因：<b>手动删除</b>＝你在控制台/号池工具点的删除；<b>Cookie失效</b>＝播放前验活自动判死；<b>到期清理</b>＝账号有效期到了自动移除。已回池（迁移到另一群或当天重登）的号不算删号。<br>通知：<b>已通知</b>＝确认发出；<b>已回池·不发</b>＝号还在跑；<b>无邮箱·不发</b>＝没登记邮箱；<b>待判·12h</b>＝删后满 12 小时才判定该不该发；<b>自动判死·run.py 发信</b>＝早期记录，发信由播放任务临时触发，发没发事后查不到。</div><div id="deadList"></div></details>
  <details class="deadbox" id="legendBox"><summary><b>标记看不懂 / 数字怎么读？点开这份对照表</b></summary><div class="lgd">
    <b>一、先认清三个数（别再混）：</b>「650进度」= 音乐人后台的 650 任务完成度，100% 才算做完，是唯一有意义的成绩；「近30日播放量」= 工作台统计的播放次数，刷再多也不直接等于进度；「其他任务」= 网易塞在同一组里的另一个小任务（多半是「发布笔记」），跟播放和 650 一点关系都没有，一列显示「—」也是正常的。
    <br><b>二、标记对照（按「问题出在哪」分组，越靠上的越该先处理）：</b>
    <table><thead><tr><th>标记</th><th>意思</th><th>要怎么处理</th></tr></thead><tbody>
    <tr><td colspan="3" style="background:#fdf0f0;font-weight:600;color:#a32d2d">A · 歌曲问题 —— 必须改歌，刷多少都不会涨</td></tr>
    <tr><td><span class="badge b-red">歌曲无效·绑错歌</span></td><td>他登记的这首歌，作者里<b>没有他自己的音乐人身份</b>（相当于绑了别人的歌）。两种情况都算：多人合唱里没他；<b>独唱但作者是别人</b>（10-25 补，只在近30日播放 ≥650 次、650 仍 ≤2% 时才提示，避免误伤爬坡中的新号）</td><td>要改：让他换成自己名下的歌。这是「播放一直涨、650 永远 0%」最常见的根因之一</td></tr>
    <tr><td><span class="badge b-red">歌曲无效·查无此歌</span></td><td>网易接口查不到这首歌（已下架或已删除）</td><td>要改：换一首正常上架的歌</td></tr>
    <tr><td><span class="badge b-orange">共创歌曲·非主艺</span></td><td>这首歌是<b>多人合唱</b>，他排在第 2 位以后（主艺是别人）。实测这类号 650 恒为 0%：合唱曲里非主艺人的播放基本不计入任务</td><td>要改：优先换本人独唱的歌</td></tr>
    <tr><td><span class="badge b-orange">共创歌曲·本人主艺</span></td><td>多人合唱，他是第一艺人。比非主艺好，但播放仍会被分摊给其他艺人，不如独唱</td><td>可改可不改：能换独唱就换</td></tr>
    <tr><td><span class="badge b-orange">共创歌曲·待核</span></td><td>多人合唱，但还没同步到该号的音乐人身份，判断不了他排第几</td><td>先按「共创」处理；等元数据同步后会自动变成上面两种之一</td></tr>
    <tr><td colspan="3" style="background:#f7f7f7;font-weight:600;color:#555">B · 账号状态</td></tr>
    <tr><td><span class="badge b-yellow">待复核</span></td><td>登录已失效被系统判死，等下一轮再确认就删号</td><td>要管：让号主换 CK</td></tr>
    <tr><td><span class="badge b-yellow">未绑邮箱</span></td><td>没填通知邮箱，号失效时通知不到人</td><td>能补就补，不影响播放</td></tr>
    <tr><td><span class="badge b-gray">只收不听</span></td><td>号主自己关了互听，只接收别人的播放，不给别人播</td><td>号主的选择，不用管</td></tr>
    <tr><td><span class="badge b-gray">公益听众</span></td><td>只用来听别人的歌的号，自己没有登记歌曲</td><td>正常，所以它没有 650 进度</td></tr>
    <tr><td colspan="3" style="background:#fdf6ec;font-weight:600;color:#b85c00">C · 任务周期（650 任务本身不统计了）</td></tr>
    <tr><td><span class="badge b-orange">有播放·650为0·卡住</span></td><td>连续 2 天以上 0% 且播放量还在涨。实测这类号 <b>11/14 是 650 任务周期已结束没续期</b>（工作台 <code>furtherVipGetTime</code> 已过期，任务不再统计播放）</td><td>要管：让号主去网易音乐人后台「领取上期奖励 / 开启新一期」</td></tr>
    <tr><td><span class="badge b-orange">有播放·650为0</span></td><td>近30日播放已有 <b>650 次以上</b>，但 650 进度是 0%：播放没被算成「有效播放」（刚开始，还看不出是不是周期问题）。入池 ≤2 天的新号不标这一类</td><td>观察 1~2 天，变成「有播放·650为0·卡住」再按上面处理</td></tr>
    <tr><td><span class="badge b-gray">无650任务</span></td><td>后台没返回 650 任务（不是音乐人 / 没报名该任务 / 歌曲未通过审核）</td><td>要管：让号主去音乐人后台确认</td></tr>
    <tr><td><span class="badge b-gray">周期归零</span>（较昨日列 + 标记列）</td><td>昨日 650 已接近满（≥80%）、今天突然 0%，但近30日播放量没塌 —— 这是 <b>650 换新周期</b>，进度从头计，不是掉量。<b>周期按 31 天日历走，不看进度</b>：上期只做到 98% 到期也一样归零重来，没用完的百分比不会带到新一期</td><td>不用管：已不计入「今日下跌」，也不再标成「有播放·650为0」</td></tr>
    <tr><td colspan="3" style="background:#fdf9e6;font-weight:600;color:#8a6d00">D · 进度停滞（还在周期内，只是没动）</td></tr>
    <tr><td><span class="badge b-yellow">今日零增长</span></td><td>650 进度和昨天完全一样（还没到 100%）</td><td>先观察 2~3 天，不是每天都一定涨</td></tr>
    <tr><td><span class="badge b-yellow">N天未涨</span></td><td>连续 N 天 650 进度没涨（含小幅回落；没有快照的断档天不计；当前已到 100% 的号不标）。<b>先看「近30日播放量」</b>：在跌 = 30 天滚动窗口里老播放退出（做过满 100% 的号会一直回落到新播放补不回为止，属自然衰减）；在涨却不动 = 播放被判无效</td><td>播放量也在跌 → 不用管；播放量在涨却 4 天不动 → 人工查</td></tr>
    <tr><td colspan="3" style="background:#eef5fd;font-weight:600;color:#255ea6">E · 入池状态 —— 刚进来的号，进度低是正常的，别当故障查</td></tr>
    <tr><td><span class="badge b-blue">今日入池</span></td><td>今天才登记的新号：明天才进轮转开始被听，所以今天既没有快照也没有 650 进度。<b>顶部「今日入池」这个数字就等于搜这个词的行数</b></td><td>正常，不用管（第 4 天还是 0% 再查）</td></tr>
    <tr><td><span class="badge b-green">已达100%</span></td><td>本周期 650 已经做满，继续刷也不会有额外收益</td><td>不用管；下个 31 天周期会自动归零重爬</td></tr>
    <tr><td colspan="3" style="background:#f7f7f7;font-weight:600;color:#555">F · 数据 / 其它</td></tr>
    <tr><td><span class="badge b-gray">采集缺失</span></td><td>今天这一轮没采到该号的快照（接口超时或号没跑）。<b>入池 ≤2 天的新号不会打这个标</b>（它们本来就没有快照，顶部「今日入池」就是它们的总数）</td><td>偶尔出现不用管，连续几天要查</td></tr>
    <tr><td><span class="badge b-red">只收</span>/<span class="badge b-yellow">长歌</span>（时长列）</td><td>时长 <b>2:12 以下</b>标红、<b>5:36 以上</b>标黄</td><td>只是提示，10-22 修完后长短歌都能正常计入</td></tr>
    </tbody></table>
    <b>三、号主来投诉「我的号不涨」时的排查顺序（照这个顺序问，一遍就能定位）：</b>
    <br>① <b>先看 A 组（歌曲）</b>：有「歌曲无效·绑错歌 / 歌曲无效·查无此歌 / 共创歌曲·非主艺」→ 直接是歌的问题，让他改歌，不用再查别的；
    <br>② <b>再看 B 组（账号）</b>：有「待复核」→ CK 已失效，号都要删了，先换 CK；
    <br>③ <b>再看 C 组（周期）</b>：有「有播放·650为0·卡住」→ 650 周期结束没续期，让他去音乐人后台开新一期（详见下面第四节）；
    <br>④ <b>再看入池天数</b>：入池 ≤2 天的号（顶部「今日入池」那批）进度低是正常爬坡，告诉他 21 天满、现在不用管；
    <br>⑤ <b>都没有</b> → 说明号是正常的，只是 650 后台分批结算（见下条）。
    <b>四、为什么没到 100% 却一天都没涨？</b>不是每天都该涨，按概率从高到低：
    <br>① <b>650 是后台分批结算的，不是实时加</b>：实测中位号一晚能跳 +30~40%，然后停一两天再突然跳一大截，所以「今天 0」很常见；
    <br>② <b>近 30 天滚动，会回吐</b>：30 天前的老播放到期退出，当天新增的有效播放少于退出的，进度就原地甚至下降（绿色负数就是这个）；
    <br>③ <b>播放 ≠ 有效播放</b>：网易按账号/IP/完整播放去重，同一个出口刷的量会被合并或丢掉。「有播放·650为0」就是这一类的信号；
    <br>④ <b>但连着 2 天以上 0% 且播放量还在涨，先查任务周期</b>：650 任务是 <b>31 天一个周期</b>，周期一结束就不再统计播放，之后刷多少都是 0。实测 10-25 当天 14 个「0% 且有播放」的号里，<b>11 个的周期结束时间已经过去</b>（最早结束 79 天前），只有 2 个还在周期内。这种只能由号主本人去网易音乐人后台「领取上期奖励 / 开启新一期」，开启后会从 0 重新爬，我们这边刷再多也没用。页面标「有播放·650为0·卡住」的就是这一类。
    <br><b>所以判断号有没有问题，看「今日零增长」连续几天 + 「近30日播放量」在涨还是在跌</b>：播放量也在跌 = 自然衰减（30天老量退出），播放量在涨但 650 一直不动 = 播放被判无效，才需要人工查。
  </div></details>
  <p style="font-size:12px;color:#888;margin:10px 0 0">数据口径：<b>650进度</b>=音乐人后台 650 任务完成度（近30日滚动，会回吐，100%=达标）；<b>近30日播放量</b>=工作台播放次数（≠有效播放，≠650进度）；<b>较昨日</b>=今天快照-昨天快照，前一日无快照显示 —（数据断层，非故障；顶部每个统计名的用词与标记列完全一致，搜索框直接搜那个词就能筛出对应行）；昨日≥80% 今日 0% 且播放量没塌的显示为灰色「周期归零」= 650 换新周期不是掉量（已从「今日下跌」剔除）；<b>其他任务</b>=与 650 无关的同组小任务（如发布笔记，按「已发x/4」显示：30 天内发布图文笔记天数≥4，4/4 即完成），显示 — 表示只有 650 一个任务；<b>时长</b>=登记歌曲长度（红=短歌&lt;2:12、黄=长歌&gt;5:36，仅提示，10-22 修完后都能正常计入）；<b>今日进度下的小字</b>=该行快照采集时间（北京时间；凌晨轮次边跑边采，不代表当天最终值，10:00 补采后的数才准）；各标记含义见上方「标记看不懂」对照表。<b>运行状态横条</b>：作业=两仓库最近一次定时轮次（GitHub API，5 分钟缓存）；应跑/实跑=按当前号池对所选日期回放的轮转计划与 runs 表核对（历史日期为近似值）；快照更新=该日快照最后写入时间（北京时间）；今日删号/待复核来自 D1。</p>
</div>
<div class="modal" id="modal" hidden><div class="mbox">
  <h3 id="mTitle">编辑账号</h3><p style="font-size:12px;color:#888;margin:4px 0 0" id="mSub"></p>
  <label>改绑歌曲（粘贴 APP 分享链接，留空不改）</label><input id="eLink" placeholder="https://163.com/... 或 song?id=...">
  <label>通知邮箱（留空不改）</label><input id="eEmail">
  <label>客服（谁录的这条，留空不改）</label><select id="eAgent"><option value="">不修改</option></select>
  <label>套餐（登记时买的时长，留空不改；<b>改套餐不会自动改有效期</b>，要一起改就把下面有效期也填上）</label>
  <select id="ePlan"><option value="">不修改</option></select>
  <label>有效期（天数 / 日期 / 永久，留空不改）</label><input id="eExp">
  <label>暂停互听（只收不听）</label><select id="eNo"><option value="">不修改</option><option value="0">参与互听</option><option value="1">暂停互听</option></select>
  <label>更换 CK（MUSIC_U，留空不改；保存前服务端会先校验有效性）</label><input id="eCk" placeholder="粘贴新的 MUSIC_U 值">
  <div class="row2"><button id="eSave">保存修改</button><button class="warn" id="eDel">删除账号</button><button class="gray" id="eCancel">关闭</button></div>
  <div class="msg" id="em"></div>
</div></div>
<div class="modal" id="cfgModal" hidden><div class="mbox">
  <h3>客服名单 / 套餐档位</h3>
  <p style="font-size:12px;color:#888;margin:4px 0 0">改完保存立即生效：APK / EXE 下次登记前会自动拉到新名单，<b>不用重新打包</b>。只读口令进不来这一页。</p>
  <label>客服（一行一个，顺序即下拉顺序）</label>
  <textarea id="cAgents" rows="5" style="width:100%;box-sizing:border-box;padding:9px;border:1px solid #ddd;border-radius:8px;font-size:13px;font-family:ui-monospace,Consolas,monospace"></textarea>
  <label>套餐（一行一个，格式 <code>显示名=天数</code>；天数填 0 表示永久）</label>
  <textarea id="cPlans" rows="4" style="width:100%;box-sizing:border-box;padding:9px;border:1px solid #ddd;border-radius:8px;font-size:13px;font-family:ui-monospace,Consolas,monospace"></textarea>
  <p style="font-size:11.5px;color:#999;margin:6px 0 0">例：<code>1年=365</code> / <code>2年=730</code> / <code>永久=0</code>。删掉某个套餐不会影响已登记的号（它们的套餐名照旧显示）。</p>
  <div class="row2"><button id="cSave">保存</button><button class="gray" id="cCancel">关闭</button></div>
  <div class="msg" id="cm"></div>
</div></div>
<script>
var TOKEN=null, DATA=null, POOLF='all';
// 2026-10-27：ROLE='full' 满权限 / 'ro' 只读（只能看，编辑、删号、客服名单全部关掉）。
// AGENTF/PLANF 是客服/套餐筛选值；AGENTS/PLANS 来自服务端 reg_cfg（控制台可改，不用重发软件）。
var ROLE='ro', AGENTF='', PLANF='', AGENTS=[], PLANS=[];
function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function todayBJ(){var d=new Date(Date.now()+8*3600*1000);return d.toISOString().slice(0,10);}
// 2026-10-27：日期范围要算「前一天」，不能再用本地时区做减法（会跨时区错一天），
// 统一按 UTC 拼日期再减，结果仍是 yyyy-mm-dd。
function dMinus(day,n){
  if(!day)return '';
  var p=String(day).split('-');
  if(p.length!==3)return '';
  var d=new Date(Date.UTC(+p[0],+p[1]-1,+p[2]));
  d.setUTCDate(d.getUTCDate()-(n||1));
  return d.toISOString().slice(0,10);
}
function api(ep,body){return fetch(ep,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});});}
// 2026-10-28（用户要求：输一次就一直有效）：控制台口令重新落盘记忆。
// 上一版是「每次都输」，理由是别把 24 位口令明文留在浏览器里；实际用下来太麻烦，改回记忆。
// 现在：登录成功 → 把 {user,pass} 连带 role 一起存进 localStorage 的 consToken。
//   存 role 是为了刷新时立刻恢复「满权限 / 只读」标签，不用等 data 回来再闪一下。
// 失效兜底：KV 里换过口令后，旧 token 请求 /api/console/data 会 403 →
//   loadData 里 dropTok() 并弹回登录框，不会卡在「一直自动登录失败」的死循环。
// 想主动清掉：点右上「退出」，走 dropTok() 删本地 token。
var TOK_KEY='consToken';
function save(t,role){
  TOKEN=t;
  var rec={t:t,role:role||""};
  try{localStorage.setItem(TOK_KEY,JSON.stringify(rec));}catch(e){}
  try{sessionStorage.removeItem(TOK_KEY);}catch(e){}
}
function load(){
  try{
    var raw=localStorage.getItem(TOK_KEY);
    if(!raw)return null;
    var rec=JSON.parse(raw);
    if(!rec||!rec.t)return null;              // 老版本残留（直接存 {user,pass}）= 认不出，重登一次
    var p=JSON.parse(rec.t);                  // token 本身仍是 {user,pass} 的 JSON 串
    if(!p||!p.user||!p.pass)return null;
    return {t:rec.t,role:rec.role||""};
  }catch(e){return null;}
}
function login(){
  var u='xx1031',p=$('lp').value;   // 2026-10-25：账号固定，登录框只留口令一个输入框
  if(!u||!p){$('lm').textContent='请输入账号和密码';$('lm').className='msg err';return;}
  $('lbtn').disabled=true;
  api('/api/console/login',{user:u,pass:p}).then(function(o){
    $('lbtn').disabled=false;
    if(o.ok&&o.d.ok){TOKEN=JSON.stringify({user:u,pass:p});save(TOKEN,o.d.role);$('loginBox').hidden=true;$('mainBox').hidden=false;applyRole(o.d.role);loadData();}
    else{$('lm').textContent=(o.d&&o.d.message)||'登录失败';$('lm').className='msg err';}
  }).catch(function(){$('lbtn').disabled=false;$('lm').textContent='网络错误';$('lm').className='msg err';});
}
$('lbtn').onclick=login;
$('lp').onkeydown=function(e){if(e.key==='Enter')login();};
$('lu').onkeydown=function(e){if(e.key==='Enter')$('lp').focus();};
$('btnOut').onclick=function(){dropTok();location.reload();};
$('btnRefresh').onclick=loadData;
// 2026-10-27 21:05：入池筛选是纯前端，改日期直接 render，不再重新请求接口（秒出）
$('date').onchange=render;$('dateTo').onchange=render;
$('dClear').onclick=function(){$('date').value='';$('dateTo').value='';render();};
$('q').oninput=render;$('sort').onchange=render;
$('fagent').onchange=function(){AGENTF=this.value;render();};
$('fplan').onchange=function(){PLANF=this.value;render();};
// 2026-10-27 二次改：入池范围控件已删（用户不要）。两个日期框都要重新拉数据，
// 因为起止日直接决定取哪两天的快照，纯前端过滤做不到。
// 2026-10-24：表格区高度自适应视口剩余空间 → 滚动发生在 .twrap 内部，配合 .twrap th 的 sticky 实现表头冻结
// 2026-10-26 修（手机端排版错乱）：手机宽度下表格已改成卡片流、整页滚动，这里绝不能再锁高度。
//   原来这里无条件写 w.style.maxHeight，手机上 innerHeight 减掉页头/统计/工具条后只剩 100 多 px，
//   被兜到 240px —— 437 张卡片全被塞进 240px 的盒子里溢出，后面的「删号记录 / 标记对照表 / 底部说明」
//   就按 240px 的位置排版，直接压在账号卡片上（用户 10-26 截图里的错乱就是这个）。
function fitTable(){
  var w=document.querySelector('.twrap');if(!w)return;
  if(window.innerWidth<=860||!w.offsetParent){w.style.maxHeight='';return;}
  var docTop=w.getBoundingClientRect().top+(window.pageYOffset||0);
  var h=window.innerHeight-docTop-18;
  w.style.maxHeight=(h>240?h:240)+'px';
}
window.addEventListener('resize',fitTable);
document.querySelectorAll('.tab').forEach(function(t){t.onclick=function(){
  document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('on');});
  t.classList.add('on');POOLF=t.getAttribute('data-p');render();};});
function accsOf(day,pool){
  // 2026-10-23 修复：/api/console/data 返回的 snap 是 {cur:{hz,dz},prev:{hz,dz}}，
  // 这里原来按 snap[日期][池] 取 → 取不到，a/p 恒为 null，
  // 导致「昨进度 / 今进度 / 日环比 / 近30日播放 / 任务」五列全空、今日有数据恒为 0。
  var S=DATA.snap||{};
  if(S.cur||S.prev){var src=(day&&day===DATA.prevDate)?S.prev:S.cur;return (src&&src[pool])||{};}
  return (S[day]&&S[day][pool])||{};
}
// ===== 2026-10-27：客服名单 / 套餐档位（服务端 reg_cfg）=====
// 下拉选项全部由服务端给，页面里不写死任何人名 —— 加人/停人只改一次配置。
function fillSel(el,items,keep,allLabel){
  var h='';
  if(allLabel!=null)h+='<option value="">'+esc(allLabel)+'</option>';
  else h+='<option value="">不修改</option>';
  h+=items.map(function(v){return '<option value="'+esc(v)+'">'+esc(v)+'</option>';}).join('');
  el.innerHTML=h;
  el.value=items.indexOf(keep)>=0?keep:'';
  return el.value;
}
function applyCfg(cfg){
  cfg=cfg||{};
  AGENTS=(cfg.agents||[]).slice();
  PLANS=(cfg.plans||[]).slice();
  AGENTF=fillSel($('fagent'),AGENTS,AGENTF,'客服：全部');
  var labels=PLANS.map(function(p){return p.label;});
  PLANF=fillSel($('fplan'),labels,PLANF,'套餐：全部');
  fillSel($('eAgent'),AGENTS,'',null);
  fillSel($('ePlan'),labels,'',null);
}
// 只读口令进来：所有写入口关掉。真正的拦截在服务端（写接口只认满权限口令），
// 前端这层只是不让人白点、也不给误操作的机会。
function applyRole(role){
  ROLE=(role==='full')?'full':'ro';
  var full=(ROLE==='full');
  $('btnCfg').style.display=full?'':'none';
  var t=$('ptitle');
  if(t){
    var old=document.getElementById('roTag');
    if(old)old.parentNode.removeChild(old);
    if(!full){
      var s=document.createElement('span');
      s.id='roTag';s.className='ro';s.textContent='只读';
      s.title='你现在用的是只读口令：可以看全部数据、可以导出，但不能改任何东西';
      t.appendChild(s);
    }
  }
}
// 2026-10-27 21:05 三次改：顶部两个日期框 = **入池日期范围**（不是快照日期）。
// 上一版把它们当「650 快照取哪两天」，结果用户选完区间表格几乎没变化 —— 因为两天快照本来
// 就长得差不多。改成按账号的 added（入池日）筛，行数立刻能看出差别。
//   · 两个都空 → 全部（跟最早的单日视图一样，不筛）
//   · 只填左边 → 这天及以后入池的
//   · 只填右边 → 这天及以前入池的
//   · 填反了自动对调（写回输入框，让用户看见实际生效的范围）
// 650 进度两列固定「昨天 vs 今天」，不再跟日期框联动。
function drngOf(){
  var a=$('date').value||'',b=$('dateTo').value||'';
  if(a&&b&&a>b){var x=a;a=b;b=x;$('date').value=a;$('dateTo').value=b;}
  return {from:a,to:b};
}
function loadData(){
  var t=JSON.parse(TOKEN||'{}');
  $('btnRefresh').disabled=true;
  // 2026-10-27 21:05：不传 date/prevDate —— 后端默认就是「昨天 vs 今天」。
  // 日期框改成筛入池日期了，再往这里塞会把筛选值污染成快照日期。
  api('/api/console/data',{user:t.user,pass:t.pass}).then(function(o){
    $('btnRefresh').disabled=false;
    if(!o.ok){if(((o.d&&o.d.message)||'').indexOf('密码')>=0){dropTok();TOKEN=null;}$('lm').textContent=o.d.message||'请重新登录';$('lm').className='msg err';$('loginBox').hidden=false;$('mainBox').hidden=true;return;}
    DATA=o.d;
    applyCfg(DATA.cfg);           // 客服/套餐下拉 + 汇总口径
    applyRole(DATA.role);         // 满权限 / 只读（服务端 data 里带，刷新一次就恢复正确权限）
    render();fitTable();
  }).catch(function(){$('btnRefresh').disabled=false;});
}
// 2026-10-24：网易工作台只回 missionCode + progressRate 两个原始字段，不翻译就是一串天书；
// 而且原来把「650 主任务」和「发布笔记」两个代码拼在一格还带 CSS 截断，看着像 650 只有 2%。
var MAIN_MISSION='mission_code_recently_play_effect_count_v2';   // 650 有效播放，与「今日650进度」列同一个数
var MIS_NAME={mission_code_musician_notebook_publish:'发布笔记'};  // 网易同组小任务，与播放无关
// 2026-10-25：progressRate 不是统一的百分比。原始接口每个子任务都带 totalCompleteNum：
// 650 主任务 totalCompleteNum=100 → progressRate 是 0~100 的百分比；
// 「发布笔记」totalCompleteNum=4（即日起30天内发布图文笔记天数≥4）→ progressRate 是
// 已发条数 0~4（全池快照实测只有 0/1/2/3/4 四个离散值）。
// 原来一律拼个 % 上去，「已发 4 条 = 4/4 早就完成」被显示成「4%」，看着像还没开始。
// 计数型任务在这里登记目标值，页面渲染成 x/4；没登记的目标值仍按百分比显示（保持旧行为）。
var MIS_TOTAL={mission_code_musician_notebook_publish:4};   // 网易任务目标值（条/天，非百分比）
function misName(k){if(MIS_NAME[k])return MIS_NAME[k];return String(k).replace(/^mission_code_/,'').replace(/_v\\d+$/,'').replace(/_/g,' ');}
// 「其他任务」列：650 主任务已在进度列显示，这里只列其余小任务并译成中文；没有就显示 —
function otherMis(a){
  if(!a||!a.mis)return '<span class="flat">—</span>';
  var h='';
  Object.keys(a.mis).forEach(function(k){
    if(k===MAIN_MISSION)return;
    var v=a.mis[k],t=MIS_TOTAL[k];
    h+='<span class="mtag">'+esc(misName(k))+' <i>'+(t?v+'/'+t:v+'%')+'</i></span>';
  });
  return h||'<span class="flat">—</span>';
}
// ===== 2026-10-25：售后诊断标签 =====
// 目标：号主来问「我这号怎么不涨/怎么归零了」，客服看这列就能直接说出原因，不用现查。
// 分组优先级（同组只出一个，避免一个号挂 5 个标签看不清）：
//   A 歌曲问题（红/橙） > B 任务周期（橙） > C 账号状态（黄） > D 入池进度（灰蓝） > E 数据（灰）
// 数据源：DATA.songs（song_meta）与 DATA.artists（acc_meta），由 tmp/sync_song_meta.py 定期回填。
var DAY_MS = 86400000;
// 入池天数：登记当天算 0（次日才开始被听）
function daysSince(added) {
  if (!added || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(String(added))) return null;
  var a = Date.parse(String(added) + 'T00:00:00Z'), t = Date.parse(String(DATA && DATA.date) + 'T00:00:00Z');
  if (isNaN(a) || isNaN(t)) return null;
  return Math.round((t - a) / DAY_MS);
}
// 歌曲归属研判 → 返回 {cls, txt, tip} 或 null
// 判据：歌曲作者数 n；本人音乐人 id 是否在作者列表里、排第几
function songVerdict(e, a) {
  var s = (DATA && DATA.songs) || {}, art = (DATA && DATA.artists) || {};
  var m = s[String(e.song)];
  if (!m) return null;                       // 元数据还没同步到这首 → 不打标签（不猜）
  if (m.g === 1) return { cls: 'b-red', txt: '歌曲无效·查无此歌',
    tip: '网易接口查不到这首歌（song_id ' + e.song + '）：已下架或已删除。播放不会进 650，让号主重新登记一首名下正常上架的独唱歌曲' };
  // 2026-10-25 补：独唱也可能「绑错歌」——这首歌只有 1 位作者，但那位作者不是该号的音乐人身份，
  // 播放同样永远不算进他的 650。为免误伤正常爬坡的新号，只在「近30日播放≥650 次却仍是 0%」时才提示。
  if ((m.n || 0) <= 1) {
    var me1 = art[String(e.uid)], only = (m.i || [])[0] || '', soloId = me1 ? (me1[0] || '') : '';
    if (soloId && only && only !== soloId && a && (a.rate || 0) <= 2 && (a.rpc30 || 0) >= 650)
      return { cls: 'b-red', txt: '歌曲无效·绑错歌',
        tip: '这首是独唱，唯一作者「' + (m.f || '—') + '」不是该号的音乐人「' + (me1[1] || soloId) + '」→ 近30日播放 ' + a.rpc30 + ' 次、650 却只有 ' + (a.rate || 0) + '%，播放基本没算到该号头上。让号主改绑到他自己名下已上架的独唱歌曲' };
    return null;                             // 独唱且作者对得上：正常，不打标签（页面上不堆无意义的绿标）
  }
  var me = art[String(e.uid)];
  if (!me) return { cls: 'b-orange', txt: '共创歌曲·待核',
    tip: '这首歌是 ' + m.n + ' 人合唱（主艺：' + (m.f || '—') + '），但还没同步到该号自己的音乐人身份，暂时判断不了他排第几。可先按「共创歌曲」处理：合唱曲里非主艺人的播放通常不算进 650，建议换一首本人独唱的歌' };
  var myId = me[0] || '';
  if (!myId) return null;                    // 该号不是音乐人 → 交给「无650任务」标签，别重复报
  var pos = (m.i || []).indexOf(myId);
  if (pos < 0) return { cls: 'b-red', txt: '歌曲无效·绑错歌',
    tip: '这首歌《' + (m.f || '') + '…》的 ' + m.n + ' 位作者里没有该号的音乐人身份（' + (me[1] || myId) + '）→ 播放再多也永远不会算进他的 650。必须改绑到他自己名下的歌' };
  if (pos > 0) return { cls: 'b-orange', txt: '共创歌曲·非主艺',
    tip: '这是 ' + m.n + ' 人合唱，该号排第 ' + (pos + 1) + ' 位（主艺是「' + (m.f || '—') + '」）。实测这类号 650 恒为 0%：合唱曲里非主艺人的播放基本不计入任务，建议改绑本人独唱的歌' };
  return { cls: 'b-orange', txt: '共创歌曲·本人主艺',
    tip: '这是 ' + m.n + ' 人合唱，该号是第一艺人。比非主艺好，但仍比独唱差（播放会被分摊到其他艺人），能换独唱就换' };
}

function buildRows(){
  if(!DATA)return[];
  var cur=DATA.snap.cur,prev=DATA.snap.prev,rows=[];
  [['hz',DATA.hz],['dz',DATA.dz]].forEach(function(pd){
    var pool=pd[0];
    pd[1].forEach(function(e){
      var a=accsOf(DATA.date,pool)[e.uid]||null,p=accsOf(DATA.prevDate,pool)[e.uid]||null;
      var delta=(a&&p&&a.rate!=null&&p.rate!=null)?(a.rate-p.rate):null;
      // 2026-10-25：周期归零判定 —— 昨日已接近满(≥80%)、今天突然 0%，但近30日播放量没塌(仍有昨日90%以上)。
      // 这是 650 任务换新周期（进度重新从 0 起算），不是掉量，不该算进「今日下跌」、也不该显示成 -100。
      // 2026-10-26 ⚠️ 实测否决：一度想改用工作台的 furtherVipGetTime（存于 DATA.periods）精确判定，
      //   但 10-26 全池实测把它证伪了 —— 按该字段「已过期」的 131 个号里 125 个当天仍在涨（95%），
      //   而「未过期」组只有 44% 在涨；字段里还出现 2024 年的日期。结论：它【不是当前周期结束日】，
      //   拿它判定会把「刚开始爬的新周期号」误标成周期到点。判定继续用原来的百分比启发式。
      //   采集链路（run.py periodEnd → console:period）保留，仅作数据留档，不参与任何判定。
      var reset=!!(a&&p&&a.rate===0&&p.rate!=null&&p.rate>=80&&(a.rpc30||0)>=(p.rpc30||0)*0.9);
      var st=(DATA.streak&&DATA.streak[pool]&&DATA.streak[pool][String(e.uid)])||0;
      rows.push({pool:pool,e:e,a:a,p:p,delta:delta,streak:st,reset:reset,
                 days:daysSince(e.added),sv:songVerdict(e,a)});
    });
  });
  return rows;
}
// 2026-10-25：标记判定抽成独立函数。① 行内渲染用；② 搜索框也能搜到「绑错歌」「共创」这类标签
// —— 售后直接搜关键词就能拉出全部同因名单，不用一个个翻。
function computeMarks(r, susSet){
  var e=r.e, a=r.a, sv=r.sv, hasSvc=!!sv, html='', txt=[];
  function add(cls,label,tip){ html+='<span class="badge '+cls+'" title="'+esc(tip)+'">'+esc(label)+'</span>'; txt.push(label); }
  // A 歌曲问题
  if(sv)add(sv.cls,sv.txt,sv.tip);
  // B 账号状态
  if(susSet[String(e.uid)])add('b-yellow','待复核','登录已失效被判死，等下一轮确认后删号，需要号主换 CK');
  if(!e.song)add('b-gray','公益听众','公益听众号：只用来听别人的歌，自己没有登记歌曲，所以没有 650 进度，属正常');
  if(!e.email)add('b-yellow','未绑邮箱','没填通知邮箱，号失效时通知不到人；不影响播放');
  if(e.noListen)add('b-gray','只收不听','号主自己关了互听：只收别人的播放，不给别人播');
  if(a&&a.rate==null&&e.song&&!(e.added&&e.added>=DATA.date))add('b-gray','无650任务','后台没返回 650 任务：可能不是音乐人、没报名该任务或歌曲未过审，让号主去音乐人后台确认');
  // C 任务周期
  // 2026-10-25 补：入池 ≤2 天的新号即使 0% 也是正常爬坡（当天登记、次日才被听），
  // 不能按「周期已结束」报，否则新号全被误标成售后问题 → 新号前 1~2 天不打标记，只在顶部「今日入池」计数。
  // 另加 rpc30>=650 门槛：播放只有个位数/几十次时 0% 只是没人听，不是「播放不计数」。
  // 2026-10-26：周期归零（昨日≥80% 今日 0%）优先判定 —— 原来这种号会被下面 hasCycle 标成
  // 「有播放·650为0」，看起来像故障，实际是换新周期。文案与「较昨日」列的灰徽章保持一致。
  // 注：不动用 furtherVipGetTime（实测不是当前周期结束日，见 buildRows 处说明）。
  if(!hasSvc&&r.reset&&e.song)add('b-gray','周期归零','昨日 650 已到 '+(r.p&&r.p.rate!=null?r.p.rate+'%':'较高')+'、今天突然 0%：650 任务 31 天周期到点，新一期从 0 重新计（不管上期做没做满，没用完的百分比直接作废）。近30日播放量没塌，属正常，不用查');
  var hasCycle=false, isNewAcc=!(r.days==null||r.days>2);
  // 2026-10-26：这里原来写「(a.rate || 0) === 0」—— rate 为 null（后台没返回 650 任务）时
  // 0 也成立，于是「无650任务」的号被同时标成「有播放·650为0」，等于告诉号主
  // 「任务周期结束了去续期」，而它压根没有任务。改成必须真有 650 进度且为 0。
  // 注意：本函数整体位于 CONSOLE_HTML 模板字符串内，注释里不能出现反引号 —— 会提前结束模板。
  if(!hasSvc&&!r.reset&&!isNewAcc&&a&&a.rate!=null&&a.rate===0&&a.rpc30!=null&&a.rpc30>=650){
    hasCycle=true;
    // 2026-10-26：原来这里叫「0%卡住·查周期」，和顶部字段「有播放·650为0」是两个名字，
    // 顶部那个数字是两类之和，但搜索框搜「有播放」搜不到卡住的号 —— 用户上次抱怨过
    // 「顶上写的数字，搜索框里搜不到」正是这类问题。现在统一成同一个前缀，只加后缀区分
    // 严重程度：搜「有播放」两类全中，搜「卡住」只中连续 0% 的那批。
    if(r.streak>=2)add('b-orange','有播放·650为0·卡住','已连续 '+(r.streak+1)+' 天 0%，播放量却还在涨。实测这类号绝大多数是 650 任务周期已经结束、没有续期（网易音乐人工作台的 furtherVipGetTime 已过期，任务不再统计播放）→ 让号主去网易音乐人后台领取上期奖励并开启新一期，开启后会从 0 重新爬');
    else add('b-orange','有播放·650为0','近30日播放已有 650 次以上，但 650 进度是 0%：播放没被算成有效播放。多数是 650 任务周期已结束没续期，见下方「标记看不懂」第三节');
  }
  // D 进度停滞
  if(!hasSvc&&!hasCycle&&a&&r.p&&a.rate!=null&&r.p.rate!=null&&a.rate<100&&a.rate-r.p.rate===0)add('b-yellow','今日零增长','650 进度和昨天完全一样。650 是后台分批结算，会停一两天再突然跳，先观察 2~3 天；若近30日播放也在跌，就是30天前老播放到期退出，属自然衰减（做过满 100% 的号会一直回落到新播放补不回为止，不是故障）');
  if(!hasSvc&&!hasCycle&&!r.reset&&a&&a.rate!=null&&a.rate<100&&r.streak&&r.streak>=2)add('b-yellow','连续'+r.streak+'天未涨','连续 '+r.streak+' 天 650 进度没涨（含小幅回落，没快照的断档天已跳过）。先看「近30日播放量」：在跌=30天滚动窗口老播放退出（做过满 100% 的号常见，属自然衰减，不用管）；在涨却不动=播放被判无效，超过 4 天才需要人工查');
  // E 入池状态
  // 2026-10-26：给当天登记的号加行内标记，这样顶部「今日入池」这个数就能被搜索框直接筛出来（顶部=行内）。
  if(String(e.added||'')===String(DATA.date))add('b-blue','今日入池','今天（'+DATA.date+'）才登记的新号：明天才进轮转开始被听，今天没有快照、650 进度是空的都属正常，不用查');
  if(e.song&&a&&(a.rate||0)>=100)add('b-green','已达100%','本周期 650 已达 100%：已经做满，不需要再刷更多（继续刷也不会有额外收益）。等下个 31 天周期重新起算会自动归零重爬');
  // 2026-10-26：删掉「次日才入池」「新号未开刷」两个标记 —— 新号前两三天进度低本来就是正常爬坡，
  // 打完标记反而制造噪音。顶部只保留一个「今日入池」总数（days<=0 的号数），行内不再重复提示。
  // F 数据
  // 2026-10-26：入池 ≤2 天的号本来就不该有快照（次日才开始被听、且新号往往还没开通任务），
  // 不能算「没采到」。原来判据是 days<=0，导致昨天登记、今天首次入池的号被误标「今日无快照」。
  // 另外「今日无快照」这个名字容易被读成「今天新入池的号」，改叫「采集缺失」，只表达数据没采到。
  if(!a&&e.song&&!(r.days!=null&&r.days<=2))add('b-gray','采集缺失','今天这一轮没采到该号快照（接口超时或号没跑），偶尔一次不用管；连续几天要查');
  return { html: html, text: txt.join(' ') };
}
// 2026-10-27 二次改：两列进度跟着日期范围换名字。跨度正好 1 天（就是原来「昨天→今天」）保持
// 原来的「昨日 / 今日 / 较昨日」；跨度大于 1 天改成「起始 / 结束 / 区间变化」——
// 否则拿 10-01 和 10-27 比还叫什么「较昨日」，标题就在撒谎。
// 2026-10-27 21:05：日期框改成筛入池日期后，650 两列固定「昨天 vs 今天」，名字不再变。
// 保留这个函数只为把真实日期写进表头 title（鼠标悬停能确认看的是哪两天）。
var LB_A='昨日650',LB_B='今日650',LB_D='较昨日';
function rangeLabels(){
  var a=(DATA&&DATA.prevDate)||'',b=(DATA&&DATA.date)||'';
  var thA=$('thA'),thB=$('thB'),thD=$('thD');
  if(thA){thA.title='昨日（'+(a||'')+'）快照里的 650 任务完成度（近30日有效播放，100%=已达标）';}
  if(thB){thB.title='今日（'+(b||'')+'）快照里的 650 任务完成度（近30日有效播放，100%=已达标）';}
  if(thD){thD.title=(a&&b?(a+' → '+b+'，'):'')+'今日650进度 - 昨日650进度；红色=涨，绿色=跌，0=今天没动，灰色「周期归零」=换新周期导致的 100→0（不是掉量）';}
  return true;
}
function render(){
  if(!DATA)return;
  var susSet={};(DATA.suspects||[]).forEach(function(s){susSet[String(s.uid)]=1;});
  renderRunbar();
  rangeLabels();                 // 必须在 buildRows 之前：行内 data-l 列名要用 LB_*
  var all=buildRows();
  all.forEach(function(r){var m=computeMarks(r,susSet);r.markHtml=m.html;r.markText=m.text;});
  var q=($('q').value||'').trim().toLowerCase();
  // 2026-10-27 21:05：入池日期范围（纯前端过滤，不重新请求接口）。
  // added 形如 2026-10-27，截前 10 位后按字符串比大小（yyyy-mm-dd 正好可比）。
  var rg=drngOf(),rOn=!!(rg.from||rg.to);
  var drEl=$('dr');if(drEl)drEl.className='dr'+(rOn?' on':'');
  var rows=all.filter(function(r){
    if(POOLF!=='all'&&r.pool!==POOLF)return false;
    // 2026-10-27：客服 / 套餐 两个下拉筛选（顶部所有统计都跟着它变）
    if(AGENTF&&String(r.e.agent||'')!==AGENTF)return false;
    if(PLANF&&String(r.e.plan||'')!==PLANF)return false;
    // 入池日期范围：没登记入池日的老号，一旦启用这个筛选就不显示（它不落在任何区间内）
    if(rOn){
      var ad=String(r.e.added||'').slice(0,10);
      if(!ad)return false;
      if(rg.from&&ad<rg.from)return false;
      if(rg.to&&ad>rg.to)return false;
    }
    if(!q)return true;
    var e=r.e;
    // 2026-10-25：搜索也能命中标记文本（如搜「绑错歌」「共创」「未开刷」直接筛出同类号）
    return ((e.name||'')+' '+(e.email||'')+' '+(e.uid||'')+' '+(e.song||'')+' '+(e.agent||'')+' '+(e.plan||'')+' '+r.markText).toLowerCase().indexOf(q)>=0;
  });
  var dnEl=$('dn');if(dnEl)dnEl.textContent=rOn?('筛出 '+rows.length+' 个'):'';
  var s=$('sort').value;
  if(s==='delta')rows.sort(function(x,y){return (y.delta==null?-999:y.delta)-(x.delta==null?-999:x.delta);});
  else if(s==='rate')rows.sort(function(x,y){return ((y.a&&y.a.rate)||-1)-((x.a&&x.a.rate)||-1);});
  var withData=rows.filter(function(r){return r.a;});
  // 2026-10-26：顶部只保留「看了要知道该不该动手」的字段。
  // 已删：平均650进度（一个池的均值没有行动意义）、次日才入池 / 新号未开刷（新号正常爬坡，行内也不打标记了）。
  // 新增：3天+未涨（真正需要人工的停滞号）、无650任务（刷多少都不会涨）、今日入池（当天新登记号数）。
  // 每个数字都来自行内标记文本，搜索框输入同一个词能拉到完全相同的行，不会再出现「顶部有数、搜不到」。
  var cntTxt=function(t){return rows.filter(function(r){return (r.markText||'').indexOf(t)>=0;}).length;};
  var ups=rows.filter(function(r){return r.delta!=null&&r.delta>0;}).length;
  var downs=rows.filter(function(r){return r.delta!=null&&r.delta<0&&!r.reset;}).length;
  var resets=cntTxt('周期归零');
  var zeroGrow=cntTxt('今日零增长');
  // 连续 N 天未涨：N 从行内「连续N天未涨」标记里取，≥3 天进这个数，≥7 天在 title 里单说。
  // 已满 100%、周期归零、歌曲有问题的号本来就不会有这个标记，所以不用再排除一次。
  var stuck3=0,stuck7=0;
  rows.forEach(function(r){var m=/连续([0-9]+)天未涨/.exec(r.markText||'');if(m){var n=+m[1];if(n>=3)stuck3++;if(n>=7)stuck7++;}});
  var noTask=cntTxt('无650任务');
  // 「有播放·650为0」和它的升级版「有播放·650为0·卡住」现在是同一个前缀（2026-10-26 改名），
  // 一次 cntTxt 就两类全算，搜索框搜「有播放」也两类全中，数字和搜索结果终于对得上。
  var played0=cntTxt('有播放·650为0');
  var svcWrong=cntTxt('歌曲无效');
  var svcCoop=cntTxt('共创歌曲');
  // 今日入池 = 行内有「今日入池」标记的行数（added 日期就是今天）。
  // 直接比日期字符串，不经过 daysSince —— 那条路径依赖正则，模板字符串里踩过一次转义的坑。
  var newIn=cntTxt('今日入池');
  var done100=cntTxt('已达100%');
  $('stats').innerHTML=
    '<div class="stat"><b>'+rows.length+'</b><span>账号总数</span></div>'
   +'<div class="stat"><b>'+withData.length+'</b><span>今日有数据</span></div>'
   +'<div class="stat"><b style="color:#c0392b">'+ups+'</b><span>今日上涨</span></div>'
   +'<div class="stat"><b style="color:#1e8449">'+downs+'</b><span>今日下跌</span></div>'
   +'<div class="stat" title="added 日期就是今天的号：明天才进轮转开始被听，今天没有快照/进度是正常的。'
   +'点「入池」列排序可以看各自登记日"><b style="color:#255ea6">'+newIn+'</b><span>今日入池</span></div>'
   +'<div class="stat"><b style="color:#888">'+resets+'</b><span>周期归零</span></div>'
   +'<div class="stat'+(zeroGrow?' warn':'')+'"><b>'+zeroGrow+'</b><span>今日零增长</span></div>'
   +'<div class="stat'+(stuck3?' warn':'')+'" title="连续 ≥3 天 650 进度没涨（已排除已满 100%、周期归零、歌曲有问题的号）。'+(stuck7?'其中 ≥7 天 '+stuck7+' 个。':'')+'先看「近30日播放量」：在跌=30天滚动窗口老播放退出（做过满 100% 的号常见，属自然衰减）；在涨却不动=播放被判无效。搜索「天未涨」可筛出这批号"><b>'+stuck3+'</b><span>3天+未涨</span></div>'
   +'<div class="stat'+(noTask?' warn':'')+'" title="后台没返回 650 任务：可能不是音乐人、没报名该任务或歌曲未过审 —— 这类号刷再多也不会涨，必须让号主去音乐人后台确认。搜索「无650任务」可筛出"><b style="color:#b85c00">'+noTask+'</b><span>无650任务</span></div>'
   +'<div class="stat'+(played0?' warn':'')+'" title="近30日播放已有 650 次以上，但 650 进度还是 0%：多数是任务周期已结束没续期。带「·卡住」后缀的是已连续 2 天以上 0%。搜索「有播放」可把两类都筛出来（搜「卡住」只看连续 0% 的那批）"><b>'+played0+'</b><span>有播放·650为0</span></div>'
   +'<div class="stat'+(svcWrong?' warn':'')+'" title="歌曲无效 = 绑错歌（歌的作者里没有他）或 查无此歌（已下架/删除）：刷多少都不会涨，必须改绑。搜索框直接搜「歌曲无效」可筛出这一类"><b style="color:#a32d2d">'+svcWrong+'</b><span>歌曲无效</span></div>'
   +'<div class="stat'+(svcCoop?' warn':'')+'" title="共创歌曲 = 多人合唱：播放会被分摊给其他艺人，非主艺的号实测恒定 0%。搜索「共创歌曲」可筛出这一类"><b style="color:#b85c00">'+svcCoop+'</b><span>共创歌曲</span></div>'
   +'<div class="stat" title="本周期已做满 100% 的号：继续刷没有额外收益，等下个 31 天周期归零重爬。搜索「已达100%」可筛出"><b>'+done100+'</b><span>已达100%</span></div>'
   ;
  // ===== 2026-10-27：套餐汇总 =====
  // 口径：按「登记时买的套餐」（accounts.plan）统计，不按剩余天数反推 —— exp 可改可续，反推会漂。
  // 三档来自服务端 reg_cfg，加档位不用改页面；存量号没套餐的单独算「未标注」，不混进任何一档。
  var planCnt={};
  rows.forEach(function(r){var k=String(r.e.plan||'');planCnt[k]=(planCnt[k]||0)+1;});
  var ph='';
  PLANS.forEach(function(p){
    var n=planCnt[p.label]||0;
    ph+='<div class="pl" data-plan="'+esc(p.label)+'" title="登记时买的是「'+esc(p.label)+'」的号：'+n+' 个（点这里可按套餐筛选）" style="cursor:pointer">'+esc(p.label)+'<b>'+n+'</b></div>';
  });
  // 配置里没有、但库里真有的历史套餐名（比如以前手输的），照样列出来，绝不吞数据
  Object.keys(planCnt).forEach(function(k){
    if(!k)return;
    if(PLANS.some(function(p){return p.label===k;}))return;
    ph+='<div class="pl muted" title="不在当前套餐档位里（历史数据），共 '+planCnt[k]+' 个">'+esc(k)+'<b>'+planCnt[k]+'</b></div>';
  });
  var noPlan=planCnt['']||0;
  if(noPlan)ph+='<div class="pl muted" title="登记时没有套餐信息的号（多半是加字段之前登记的老号）">未标注<b>'+noPlan+'</b></div>';
  $('plans').innerHTML=ph||'';
  // 套餐条点击 = 按该档筛选。用 data-plan + 事件委托，不写内联 onclick ——
  // 这段 JS 本身住在模板字符串里，内联写法要跨两层转义，10-27 就因为这个把整段脚本写崩过。
  $('plans').onclick=function(ev){
    var el=ev.target;
    while(el&&el!==this&&!(el.getAttribute&&el.getAttribute('data-plan')))el=el.parentNode;
    if(!el||el===this||!el.getAttribute)return;
    pickPlan(el.getAttribute('data-plan'));
  };
  // 2026-10-27：套餐和有效期是**两个字段**——套餐（plan）只用于统计口径，真正卡播放/互听时长的是有效期（exp）。
  // 手动改有效期不会自动改套餐，所以两边可能对不上（比如选了「1年」又把有效期改到 730 天）。
  // 这里只在渲染时标一个「≠」提示，不改任何数据、不拦任何操作。
  function planDaysOf(label){for(var i=0;i<PLANS.length;i++){if(PLANS[i].label===label)return PLANS[i].days;}return null;}
  function actualDaysOf(e){
    var x=String(e.exp||'').trim();
    if(!x||x==='forever'||x==='永久')return 0;                 // 0 = 永久
    var t1=Date.parse(x.slice(0,10)+'T00:00:00Z'),t2=Date.parse(String(e.added||'').slice(0,10)+'T00:00:00Z');
    if(isNaN(t1)||isNaN(t2))return null;
    return Math.round((t1-t2)/864e5);
  }
  var h='';
  rows.forEach(function(r,i){
    var e=r.e,a=r.a;
    var rateNow=a&&a.rate!=null?a.rate:'—',ratePrev=r.p&&r.p.rate!=null?r.p.rate:'—';
    var dCell=r.delta==null?'<span class="flat">—</span>':(r.reset?'<span class="badge b-gray" title="650 任务按 31 天一个周期结算：上一周期已结束、新周期从头计，所以今天变 0% 不是掉量（近30日播放量并没有塌）。不计入「今日下跌」，通常几天内会重新爬回">周期归零</span>':(r.delta>0?'<span class="up">+'+r.delta+'</span>':(r.delta<0?'<span class="down">'+r.delta+'</span>':'<span class="flat">0</span>')));
    var misCell=otherMis(a);
    var song=e.song?'<a class="song" target="_blank" href="https://music.163.com/song?id='+e.song+'">'+e.song+'</a>':'<span style="color:#bbb">公益</span>';
    var dur=(DATA.durs||{})[r.pool+'|'+e.uid]||(DATA.durs||{})[e.uid]||((a&&a.dur)||0);
    var durCell='<span class="flat">—</span>';
    if(dur>0){var mm=Math.floor(dur/60),ss=('0'+(dur%60)).slice(-2);
      durCell=dur<132?'<span class="badge b-red" title="短歌（不到 2:12）：10-22 时长 Bug 已修，现在短歌也能正常计入，这里只是提示">'+mm+':'+ss+'</span>'
        :(dur>336?'<span class="badge b-yellow" title="长歌（超过 5:36）：单次播放耗时长，会拖慢单班进度">'+mm+':'+ss+'</span>'
        :'<span class="num">'+mm+':'+ss+'</span>');}
    var marks=r.markHtml||'';   // 2026-10-25：标记已在 render 开头由 computeMarks 算好（搜索框也能命中）
    // 2026-10-27：客服 / 套餐两列；data-l 提供手机端卡片标签（列顺序变了标签不会跟着错）。
    var agCell=e.agent?'<span class="badge b-gray" title="这条登记是 '+esc(e.agent)+' 录的">'+esc(e.agent)+'</span>':'<span style="color:#ccc">—</span>';
    var plCell='';
    if(!e.plan){plCell='<span style="color:#ccc">未标注</span>';}
    else{
      plCell=esc(e.plan);
      var _pd=planDaysOf(e.plan),_ad=actualDaysOf(e);
      if(_pd!==null&&_ad!==null&&Math.abs(_ad-_pd)>10){
        plCell+='<span class="badge b-yellow" style="margin-left:4px" title="套餐记的是「'+esc(e.plan)+'」（'+(_pd?(_pd+' 天'):'永久')+'），但按入池日算有效期实际是 '+(_ad?(_ad+' 天'):'永久')+'。两个字段互相独立：套餐只影响统计口径，卡时长的是有效期；改一边不会自动改另一边。">≠</span>';
      }
    }
    var opCell=(ROLE==='full')
      ? '<button class="mini" style="padding:4px 10px;font-size:12px" data-pool="'+r.pool+'" data-uid="'+esc(e.uid)+'" data-name="'+esc(e.name)+'">编辑</button>'
      : '<span style="color:#c9ced6;font-size:12px">只读</span>';
    h+='<tr><td class="num">'+(i+1)+'</td>'
      +'<td><span class="badge '+(r.pool==='hz'?'b-hz">主群':'b-dz">定制')+'</span></td>'
      +'<td>'+esc(e.name)+'</td>'
      +'<td>'+agCell+'</td>'
      +'<td class="num" data-l="UID">'+esc(e.uid)+'</td>'
      +'<td class="num" data-l="歌曲">'+song+'</td>'
      +'<td data-l="时长">'+durCell+'</td>'
      +'<td class="num" data-l="'+LB_A+'">'+ratePrev+'</td>'
      +'<td class="num" data-l="'+LB_B+'" style="font-weight:600">'+rateNow+(a&&a.at?'<div class="snap-at">采于 '+bjTime(a.at)+'</div>':'')+'</td>'
      +'<td data-l="'+LB_D+'">'+dCell+'</td>'
      +'<td class="num" data-l="近30日播放">'+(a&&a.rpc30!=null?a.rpc30:'—')+'</td>'
      +'<td data-l="其他任务">'+misCell+'</td>'
      +'<td class="num" data-l="入池">'+esc(e.added)+'</td>'
      +'<td class="num" data-l="有效期">'+esc(e.exp||'永久')+'</td>'
      +'<td data-l="套餐">'+plCell+'</td>'
      +'<td>'+(marks||'<span style="color:#bbb">正常</span>')+'</td>'
      +'<td>'+opCell+'</td></tr>';
  });
  $('tb').innerHTML=h||'<tr><td colspan="17" style="text-align:center;color:#999;padding:20px">没有匹配的账号</td></tr>';
}
// 点顶部的套餐卡片 = 直接按这个套餐筛选（再点一次取消）
function pickPlan(label){
  var el=$('fplan');
  if(!el)return;
  PLANF=(el.value===label)?'':label;
  el.value=PLANF;
  render();
}
// 2026-10-23：运行状态横条（作业状态/应跑实跑/快照新鲜度/今日删号与待复核）
function bjTime(iso){if(!iso)return '';var d=new Date(iso);if(isNaN(d.getTime()))return '';var b=new Date(d.getTime()+8*3600*1000);return ('0'+(b.getUTCMonth()+1)).slice(-2)+'-'+('0'+b.getUTCDate()).slice(-2)+' '+('0'+b.getUTCHours()).slice(-2)+':'+('0'+b.getUTCMinutes()).slice(-2);}
function renderRunbar(){
  if(!DATA)return;
  var A=DATA.actions||[],C=DATA.coverage||{},F=DATA.fresh||{},D=DATA.dead||[],S=DATA.suspects||[];
  var h='';
  A.forEach(function(a){
    var label=a.pool==='hz'?'主群作业':'定制群作业';
    if(a.ok){
      var good=a.conclusion==='success';
      var jobTxt=a.jobs_total?(' · '+a.jobs_ok+'/'+a.jobs_total+' job'):'';
      h+='<div class="rb"><b>'+label+'</b> <span class="'+(good?'good':'bad')+'">'+(good?'✓ 成功':'✗ '+esc(a.conclusion||'失败'))+esc(jobTxt)+'</span><br>'
        +'<span class="muted">'+bjTime(a.created)+(a.url?' · <a href="'+esc(a.url)+'" target="_blank">日志</a>':'')+'</span></div>';
    }else{
      h+='<div class="rb"><b>'+label+'</b> <span class="muted">'+(a.note?esc(a.note):'未配置')+'</span></div>';
    }
  });
  var covH='';
  ['hz','dz'].forEach(function(p){
    var c=C[p];
    if(!c){covH+='<span class="muted">'+(p==='hz'?'主群':'定制群')+':无计划</span> ';return;}
    var cls=c.missing.length?'bad':'good';
    covH+='<span class="'+cls+'">'+(p==='hz'?'主群':'定制群')+' '+c.ran+'/'+c.expected+(c.missing.length?' 缺'+c.missing.length:'')+'</span> ';
  });
  h+='<div class="rb"><b>应跑/实跑</b><br>'+covH+'</div>';
  var fr='';
  ['hz','dz'].forEach(function(p){if(F[p])fr+='<span class="muted">'+(p==='hz'?'主群':'定制群')+' '+bjTime(F[p])+'</span> ';});
  h+='<div class="rb"><b>快照更新至</b><br>'+(fr||'<span class="muted">当日无快照</span>')+'</div>';
  // 2026-10-26：「当日删号」原来直接数 dead_log 里今天有几条，但删完又登记回来的号
  // （迁移到定制群、当天重登）也被算成删号，右上角就会一直挂着一个并不存在的「删了 1 个」。
  // 现在拿当日删除明细和当前号池做差集：uid 还在任一池里 = 已回池，不算删号。
  var liveUid={};
  (DATA.hz||[]).concat(DATA.dz||[]).forEach(function(e){if(e&&e.uid)liveUid[String(e.uid)]=1;});
  var dl=(DATA.deadToday||(function(){return D.filter(function(d){return (d.at||'').slice(0,10)===DATA.date;});})());
  var deadReal=0, deadBack=0;
  dl.forEach(function(x){ if(liveUid[String(x.uid)])deadBack++; else deadReal++; });
  h+='<div class="rb"><b>当日删号</b> <span class="'+(deadReal?'bad':'muted')+'">'+deadReal+'</span>'
    +(deadBack?' · <b>已回池</b> <span class="good">'+deadBack+'</span>':'')
    +' · <b>待复核</b> <span class="'+(S.length?'bad':'good')+'">'+S.length+'</span></div>';
  $('runbar').innerHTML=h;
  if(D.length||S.length){
    $('deadBox').hidden=false;
    var dh='';
    // 2026-10-26：「通知号主」列。cookie_invalid 是 run.py 当场发信，恒为已通知；
    // 手动删号要等 12 小时才判（迁移/重登不发），所以会先显示「待判」。
    function ntTxt(d){
      var st=d.notice;
      // 2026-10-26：老记录（没有 dead_notice 行）原来对 cookie_invalid 一律显示「已通知」，
      // 但这是「机制上应该发」而不是「查得到的已发」——10-23 那批手工调接口删的就没有 run.py
      // 在场，一封都没出去。改成描述触发方式，不断言送达。可在图例里看口径。
      if(!st){ return (d.reason||'')==='cookie_invalid'?'<span class="muted">自动判死·run.py 发信</span>':'<span class="muted">—</span>'; }
      if(st.state==='sent')return '<span class="good">已通知</span>';
      if(st.state==='claimed')return '<span class="muted">发送中</span>';
      if(st.state==='skip_returned')return '<span class="good">已回池·不发</span>';
      if(st.state==='skip_noemail')return '<span class="muted">无邮箱·不发</span>';
      // 过了判定窗口还在 pending ＝ 已经判过、发信失败被退回重试（notify_dead 的回执），
      // 这时候再写「待判·12h」会让人以为系统还没干活。
      // 2026-10-26 修复：removed_at 是 bjStamp() 生成的【北京时间】字符串，原来直接拼 'Z'
      // 当 UTC 解析，基准差 8 小时 → 「待判·12h」实际要到 21 小时才变「待发送·重试中」。
      // 带时区后缀的值原样解析，不带后缀的一律按 +08:00 解释。
      var rawT=String(st.removed_at||'');
      var t0=Date.parse(/[Zz]$|[+-][0-9]{2}:[0-9]{2}$/.test(rawT)?rawT:(rawT.replace(' ','T')+'+08:00'));
      if(!isNaN(t0)&&(Date.now()-t0)>13*3600000)return '<span class="muted">待发送·重试中</span>';
      return '<span class="muted">待判·12h</span>';
    }
    // 2026-10-26：原因列原来是 D1 内部英文码（manual / cookie_invalid / expired），
    // 对内看是「同一个词反复出现、看不出区别」，对外也看不懂。这里翻成中文并说清区别。
    function rsTxt(r){
      r=String(r||'');
      if(r==='manual')return '手动删除<span class="muted">·控制台</span>';
      if(r==='cookie_invalid')return 'Cookie失效<span class="muted">·自动判死</span>';
      if(r==='expired')return '到期清理<span class="muted">·自动</span>';
      if(r==='unknown'||!r)return '<span class="muted">—</span>';
      return esc(r);
    }
    // 2026-10-26：10-23 那批清理脚本把 name 写成「manual:<uid>」了，D1 已就地修正，
    // 这里再兜一层，避免老数据或别处再传脏值。
    function nmTxt(n){ return esc(String(n||'').replace(/^manual:/,'')); }
    D.slice(0,12).forEach(function(d){dh+='<tr><td>'+(d.pool==='hz'?'主群':'定制')+'</td><td class="num">'+esc(d.uid)+'</td><td>'+nmTxt(d.name)+'</td><td>'+rsTxt(d.reason)+'</td><td>'+ntTxt(d)+'</td><td class="num">'+esc((d.at||'').slice(5,16))+'</td></tr>';});
    S.slice(0,12).forEach(function(s){dh+='<tr><td>'+(s.pool==='hz'?'主群':'定制')+'</td><td class="num">'+esc(s.uid)+'</td><td>'+esc(s.name)+'</td><td colspan="3">待复核（suspect_at '+esc((s.since||'').slice(0,16))+'）</td></tr>';});
    $('deadList').innerHTML='<table><thead><tr><th>池</th><th>UID</th><th>账号</th><th>原因</th><th>通知</th><th>时间</th></tr></thead><tbody>'+dh+'</tbody></table>';
  }
}
window.openEdit=function(pool,uid,name){
  $('eLink').value='';$('eEmail').value='';$('eExp').value='';$('eNo').value='';$('eCk').value='';$('em').textContent='';
  // 2026-10-27：客服/套餐下拉每次打开都按当前配置重建（名单可能在别的标签页刚改过）
  applyCfg(DATA&&DATA.cfg);
  if($('eAgent'))$('eAgent').value='';
  if($('ePlan'))$('ePlan').value='';
  $('mTitle').textContent='编辑账号 · '+(pool==='hz'?'主群':'定制群');
  $('mSub').textContent=name+(uid?' / uid '+uid:'');
  $('modal').hidden=false;
  $('eSave').onclick=function(){doEdit(pool,{uid:uid,name:name},'update');};
  $('eDel').onclick=function(){if(confirm('确定从'+(pool==='hz'?'主群':'定制群')+'删除账号 '+(name||uid)+'？删除后不能恢复。12 小时内没有重新登记回来（含迁到另一群），系统会自动给号主发一封「账号信息过期」邮件。'))doEdit(pool,{uid:uid,name:name},'delete');};
};
// 事件委托：表格内点「编辑」按钮（data-pool 属性路由到 openEdit），不受行重绘影响
$('tb').addEventListener('click',function(ev){
  var b=ev.target;
  while(b&&b!==this&&!(b.getAttribute&&b.getAttribute('data-pool')))b=b.parentNode;
  if(b&&b!==this&&b.getAttribute)openEdit(b.getAttribute('data-pool'),b.getAttribute('data-uid')||'',b.getAttribute('data-name')||'');
});
function doEdit(pool,e,action){
  var t=JSON.parse(TOKEN||'{}');
  var body={user:t.user,pass:t.pass,pool:pool,action:action,uid:e.uid,name:e.name};
  if(action==='update'){
    body.link=$('eLink').value.trim();body.email=$('eEmail').value.trim();body.exp=$('eExp').value.trim();body.ck=$('eCk').value.trim();
    if($('eNo').value!=='')body.noListen=$('eNo').value==='1';
    // 2026-10-27：留空=不改（与其它栏一致）
    if($('eAgent').value)body.agent=$('eAgent').value;
    if($('ePlan').value)body.plan=$('ePlan').value;
  }
  $('eSave').disabled=true;$('eDel').disabled=true;
  api('/api/console/entry',body).then(function(o){
    $('eSave').disabled=false;$('eDel').disabled=false;
    if(o.ok&&o.d.ok){$('em').textContent=o.d.message||'已保存';$('em').className='msg ok';setTimeout(function(){$('modal').hidden=true;loadData();},900);}
    else{$('em').textContent=(o.d&&o.d.message)||'操作失败';$('em').className='msg err';}
  }).catch(function(){$('eSave').disabled=false;$('eDel').disabled=false;$('em').textContent='网络错误';$('em').className='msg err';});
}
$('eCancel').onclick=function(){$('modal').hidden=true;};
// ===== 2026-10-27：客服名单 / 套餐档位维护（只读口令看不到这个按钮，服务端也会拦）=====
// 客服一行一个；套餐一行一个「显示名=天数」，天数 0 = 永久。改完保存，APK/EXE 下次登记自动拿到。
$('btnCfg').onclick=function(){
  var c=(DATA&&DATA.cfg)||{agents:[],plans:[]};
  $('cAgents').value=(c.agents||[]).join('\\n');
  $('cPlans').value=(c.plans||[]).map(function(p){return p.label+'='+p.days;}).join('\\n');
  $('cm').textContent='';$('cfgModal').hidden=false;
};
$('cCancel').onclick=function(){$('cfgModal').hidden=true;};
$('cSave').onclick=function(){
  var t=JSON.parse(TOKEN||'{}');
  var agents=$('cAgents').value.split('\\n').map(function(s){return s.trim();}).filter(Boolean);
  var plans=$('cPlans').value.split('\\n').map(function(s){
    s=s.trim();if(!s)return null;
    var q=s.split('=');if(q.length<2)return null;
    var lb=q[0].trim(),dy=parseInt(q[1],10);
    if(!lb||isNaN(dy))return null;
    return {key:lb,label:lb,days:dy};
  }).filter(Boolean);
  if(!agents.length||!plans.length){$('cm').textContent='客服和套餐至少要各留一条';$('cm').className='msg err';return;}
  $('cSave').disabled=true;
  api('/api/console/cfg',{user:t.user,pass:t.pass,agents:agents,plans:plans}).then(function(o){
    $('cSave').disabled=false;
    if(o.ok&&o.d.ok){$('cm').textContent=o.d.message||'已保存';$('cm').className='msg ok';setTimeout(function(){$('cfgModal').hidden=true;loadData();},900);}
    else{$('cm').textContent=(o.d&&o.d.message)||'保存失败';$('cm').className='msg err';}
  }).catch(function(){$('cSave').disabled=false;$('cm').textContent='网络错误';$('cm').className='msg err';});
};
$('btnCsv').onclick=function(){
  var rows=[[ '池','账号','客服','套餐','UID','歌曲ID','时长(秒)',
    '昨进度','今进度','日环比',
    '近30日播放','入池','有效期','邮箱','标记']];
  buildRows().forEach(function(r){
    var e=r.e;
    var dur=(DATA.durs||{})[r.pool+'|'+e.uid]||(DATA.durs||{})[e.uid]||((r.a&&r.a.dur)||'');
    rows.push([r.pool==='hz'?'主群':'定制群',e.name,e.agent||'',e.plan||'',e.uid||'',e.song||'',dur,
      r.p&&r.p.rate!=null?r.p.rate:'',r.a&&r.a.rate!=null?r.a.rate:'',r.delta==null?'':r.delta,
      r.a&&r.a.rpc30!=null?r.a.rpc30:'',e.added||'',e.exp||'永久',e.email||'',e.noListen?'只收':'']);
  });
  var csv='\\ufeff'+rows.map(function(r){return r.map(function(v){return '"'+String(v).replace(/"/g,'""')+'"';}).join(',');}).join('\\r\\n');
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='650控制台_'+(DATA?DATA.date:todayBJ())+'.csv';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
};
(function(){
  // 2026-10-27 21:05：入池日期范围默认留空 = 全部号（不筛）。要看某段就自己填。
  $('dateTo').value='';
  $('date').value='';
  // 2026-10-25：#pw= 免密改成「可重复触发」。旧版只在脚本初次执行时读一次 hash，而 CK助手再点
  // 「进阶控制台」时浏览器通常已经开着 /console 标签 —— 那只是同页内 hash 变化，脚本不会重跑，
  // 免密不执行 → 刚在 EXE 输过口令，网页又弹登录框（等于要输两遍）。现在抽成函数并监听 hashchange。
  function hashLogin(){
    var m=(location.hash||'').match(/pw=([^&]+)/)||(location.search||'').match(/[?&]pw=([^&]+)/);
    if(!m)return false;
    var pw=m[1];try{pw=decodeURIComponent(pw);}catch(e){}
    try{history.replaceState(null,'',location.pathname);}catch(e1){}   // 地址栏/历史不留明文口令
    var lb=$('loginBox'),mb=$('mainBox');
    $('lp').value=pw;
    $('lm').textContent='正在自动登录…';$('lm').className='msg';
    api('/api/console/login',{user:'xx1031',pass:pw}).then(function(o){
      if(o.ok&&o.d.ok){
        TOKEN=JSON.stringify({user:'xx1031',pass:pw});save(TOKEN,o.d.role);
        lb.hidden=true;mb.hidden=false;applyRole(o.d.role);loadData();
      }else{
        lb.hidden=false;mb.hidden=true;
        $('lm').textContent=(o.d&&o.d.message)||'免密登录失败，请重新输入控制台口令';$('lm').className='msg err';
      }
    }).catch(function(){
      lb.hidden=false;mb.hidden=true;
      $('lm').textContent='网络错误，请手动登录';$('lm').className='msg err';
    });
    return true;
  }
  window.addEventListener('hashchange',function(){hashLogin();});
  if(hashLogin())return;                    // 带 #pw= 时优先免密，不看缓存
  var s=load();
  if(s){TOKEN=s.t;applyRole(s.role);$('loginBox').hidden=true;$('mainBox').hidden=false;loadData();}
})();
</script></body></html>`;

// 2026-10-22：D1 绑定只支持 ES Module 格式，故入口从 addEventListener 改为
// export default { fetch }。既有代码全部按 service-worker 时代的「绑定即全局变量」
// 写法（POOL.get / GH_OWNER ...），这里在每个请求开头把 env 挂到 globalThis，
// 一行代码都不用改旧的。绑定对同一 isolate 的所有请求完全相同，挂全局是安全的。
export default {
  async fetch(request, env, ctx) {
    globalThis.POOL = env.POOL;
    globalThis.GH_OWNER = env.GH_OWNER;
    globalThis.GH_REPO = env.GH_REPO;
    if (env.DB) globalThis.DB = env.DB;
    // 2026-10-25：handle(request) 拿不到 ctx（签名只有 request），想用 waitUntil 做后台任务
    // 必须挂到全局。不挂的话路由里引用 ctx 会抛 ReferenceError，被 try/catch 吞掉 → 后台任务静默不执行。
    if (ctx) globalThis.CTX = ctx;
    try {
      return await handle(request);
    } catch (e) {
      return new Response(JSON.stringify({ message: '服务器内部错误：' + ((e && e.message) || e) }),
        { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
    }
  },
  // 2026-10-24：CF 原生 cron 入口。只做一件事 —— 准点把 snap650 的 workflow_dispatch 叫起来。
  // 之所以不用 GitHub 的 schedule：本账号实测 schedule 会整体推迟 1~5 小时（relay 22:23→02:25），
  // snap650 上线两天甚至 0 次自动运行，导致控制台白天读到的仍是凌晨结算前的旧值。
  async scheduled(event, env, ctx) {
    globalThis.POOL = env.POOL;
    globalThis.GH_OWNER = env.GH_OWNER;
    globalThis.GH_REPO = env.GH_REPO;
    if (env.DB) globalThis.DB = env.DB;
    ctx.waitUntil(dispatchSnap650('all').catch(() => {}));
    // 2026-10-25：每天顺手补一批歌曲/账号元数据（控制台「共创歌曲 / 绑错歌」标签的数据源）。
    // 本地 IP 被网易限流，只能靠 Worker 出口；每天 30 个号 + 12 首歌，新号基本当天就能补上。
    ctx.waitUntil(backfillMeta().catch(() => {}));
  }
};
