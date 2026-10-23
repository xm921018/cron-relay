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

async function neteaseSendCode(phone) {
  try {
    const body = await weapi({ cellphone: phone, ctcode: '86' });
    const r = await fetch(`${BASE}/weapi/sms/captcha/sent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA, Referer: BASE + '/', Origin: BASE },
      body: new URLSearchParams(body).toString(),
    });
    const txt = await r.text();
    let j = null;
    try { j = JSON.parse(txt); } catch (e) {}
    if (j && j.code === 200) return { ok: true };
    return { ok: false, msg: '短信发送失败：HTTP ' + r.status + (j ? ' code=' + j.code : '，响应：' + txt.slice(0, 60)) };
  } catch (e) {
    return { ok: false, msg: '短信发送异常（网易接口暂不可达）：' + ((e && e.message) || e) };
  }
}

async function neteaseLogin(phone, code) {
  try {
    const body = await weapi({ phone, countrycode: '86', captcha: code, rememberLogin: 'true' });
    const r = await fetch(`${BASE}/weapi/login/cellphone`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA, Referer: BASE + '/', Origin: BASE },
      body: new URLSearchParams(body).toString(),
    });
    const j = await r.json();
    if (j.code !== 200) return { ok: false, msg: '登录失败 code=' + j.code + (j.message ? '（' + j.message + '）' : '') };
    const ck = j.cookie || '';
    let musicU = '';
    const m = ck.match(/MUSIC_U=([^;]+)/);
    if (m) musicU = m[1];
    if (!musicU) {
      const h = r.headers.get('set-cookie') || '';
      const m2 = h.match(/MUSIC_U=([^;]+)/);
      if (m2) musicU = m2[1];
    }
    if (!musicU) return { ok: false, msg: '未取到登录凭证' };
    return { ok: true, musicU, uid: (j.profile || {}).userId };
  } catch (e) {
    return { ok: false, msg: '登录请求异常（网易接口暂不可达）：' + ((e && e.message) || e) };
  }
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
    _cfg = {
      ghToken: cleanKV(await POOL.get('GH_TOKEN')),
      groupPass: cleanKV(await POOL.get('GROUP_PASS')),
      groupPass2: cleanKV(await POOL.get('GROUP_PASS2')),
      adminPass: cleanKV(await POOL.get('ADMIN_PASS')),
      // 分配接口独立口令（2026-10-22）：/api/assign 会下发明文 CK，绝不能用发给全体成员的群口令，
      // 否则任何成员循环 job=0..N 就能把全池 MUSIC_U 拖走。未配置时该接口直接拒绝服务。
      assignPass: cleanKV(await POOL.get('ASSIGN_PASS')),
      // 分群上限：2026-10-22 默认 500 → 1500，同日晚按「20 并发 + 24h 排队上限」下调到 1200
      // （KV 里 POOL_LIMIT_G1 / POOL_LIMIT_G2 仍可覆盖，改数字即时生效不用改代码）
      poolLimit: parseInt(cleanKV(await POOL.get('POOL_LIMIT')), 10) || 1200,
      poolLimitG1: parseInt(cleanKV(await POOL.get('POOL_LIMIT_G1')), 10) || 1200,
      poolLimitG2: parseInt(cleanKV(await POOL.get('POOL_LIMIT_G2')), 10) || 500,
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
// ---- 分群计数辅助：历史条目没有 grp 字段的一律算一群 ----
const grpOf = e => (Number(e && e.grp) === 2 ? 2 : 1);
const groupLimitOf = (c, isG2) => (isG2 ? c.poolLimitG2 : c.poolLimitG1);
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

function d1ok() {
  try { return typeof DB !== 'undefined' && DB && typeof DB.prepare === 'function'; } catch (e) { return false; }
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

async function d1Run(sql, params) {
  if (!d1ok()) return false;
  try {
    const st = DB.prepare(sql);
    if (params && params.length) await st.bind(...params).run(); else await st.run();
    return true;
  } catch (e) { console.error('D1 run 失败:', e && e.message); return false; }
}
// 单条镜像（新增/修改后调用）；无 uid 的历史条目跳过（无法按 uid 定位）
async function d1Upsert(e) {
  if (!d1ok() || !e) return false;
  const uid = e.uid != null ? String(e.uid) : '';
  if (!uid) return false;
  return d1Run(
    'INSERT INTO accounts (pool,uid,name,song,ck,added,exp,no_listen,email,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?) ' +
    'ON CONFLICT(pool,uid) DO UPDATE SET name=excluded.name, song=excluded.song, ck=excluded.ck, ' +
    'added=excluded.added, exp=excluded.exp, no_listen=excluded.no_listen, email=excluded.email, ' +
    'updated_at=excluded.updated_at',
    [POOL_NAME, uid, String(e.name || ''), String(e.song || ''), String(e.ck || ''), String(e.added || ''),
     String(e.exp || ''), e.noListen ? 1 : 0, String(e.email || ''), new Date().toISOString()]
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
const D1_COLS = 'uid,name,song,ck,added,exp,no_listen,email';

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
    const stmts = uids.map(uid => DB.prepare(
      'INSERT INTO snapshots (day,pool,uid,rate,rpc30,cnt,missions,dur,at) VALUES (?,?,?,?,?,?,?,?,?) ' +
      'ON CONFLICT(day,pool,uid) DO UPDATE SET rate=excluded.rate, rpc30=excluded.rpc30, ' +
      'cnt=excluded.cnt, missions=excluded.missions, dur=excluded.dur, at=excluded.at'
    ).bind(day, pool, String(uid), clean[uid].rate, clean[uid].rpc30, clean[uid].cnt,
           JSON.stringify(clean[uid].mis || {}), clean[uid].dur, now));
    await DB.batch(stmts);
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
    // 本地后台网页（号池管理网页.html）跨域调用本接口：放开 CORS 并处理预检
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
      const peerPass = cleanKV(await POOL.get('PEER_PASS'));
      if (!peerPass) return json({ message: '未开启跨群互听：请在 KV 添加 PEER_PASS 键' }, 503, CORS);
      const c = await cfg();
      if ((url.searchParams.get('pass') || '') !== peerPass) return json({ message: '口令错误' }, 403, CORS);
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
      if (need.length) {
        const uids = need.map(x => x.uid);
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
    if (url.pathname === '/api/sendcode' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      // 2026-10-13 修复：此前唯一没挂群口令的写接口，可被匿名调用给任意手机号发验证码短信
      // 2026-10-20 应用户要求群口令整体取消（本接口也不再校验）；如需防短信滥用请另加频率限制
      const c0 = await cfg();
      const gp0 = groupPassCheck(c0, body);
      if (!gp0.ok) return json({ message: gp0.msg }, gp0.status);
      // 2026-10-22 补频控：本接口按设计不带口令，任何人都能调。被拿去给任意号码发短信（轰炸）时，
      // 污染的是 worker 的出口 IP，会连带影响登录/校验。这里按出口 IP 每天限 10 次。
      const ip = String(request.headers.get('CF-Connecting-IP') || 'unknown').slice(0, 64);
      const rk = 'sc:' + ip + ':' + beijingDate();
      // 2026-10-22 第三批：计数从 KV 改到 D1 rate_limit 表（原子自增）。
      // KV 版是「读→加一→写回」，并发请求会读到同一个旧值、各写回同一个 n+1 → 10 次上限可被
      // 并发绕过；且 KV 免费额度写只有 1000 次/天。D1 不可用时才回退 KV，绝不让频控静默失效。
      let hits = await d1Hit('sc', ip + ':' + beijingDate());
      if (hits === null) {
        try {
          const cnt = parseInt(await POOL.get(rk), 10) || 0;
          hits = cnt + 1;
          if (cnt < 10) await POOL.put(rk, String(hits), { expirationTtl: 172800 });
        } catch (e) { hits = 0; }
      }
      if (hits > 10) return json({ message: '今日验证码发送次数过多，请明天再试，或改用方式二（粘贴 MUSIC_U）' }, 429);
      const send = await neteaseSendCode(body.phone);
      if (!send.ok) return json({ message: send.msg }, 400);
      return json({ message: 'ok' });
    }
    if (url.pathname === '/api/join' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      const gp1 = groupPassCheck(c, body);
      if (!gp1.ok) return json({ message: gp1.msg }, gp1.status);
      // 号池满员闸口（一群上限 POOL_LIMIT_G1 默认 1500，2026-10-22 由 500 上调）；
      // 二群已独立为 dingzhi 系统，主 worker 一律按一群计数与登记
      const isG2 = false;
      const myLimit = groupLimitOf(c, isG2);
      const _m1 = await mergePool();
      // 2026-10-22 修正计数口径：mergePool 只读本 worker 自己那一池（WHERE pool=POOL_NAME），
      // 所以行数就是本群人数。原来按 grpOf(e) 数，而 D1 表没有 grp 列 → 计数恒 0 → 上限永不生效。
      const grpUsed = _m1.length;
      if (grpUsed >= myLimit) return json({ message: '本群名额已满（上限 ' + myLimit + ' 人），暂停登记。已有账号的互听和签到不受影响，请稍后再试或联系群主。' }, 429);
      const email = (body.email || '').trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ message: '请填写常用邮箱' }, 400);
      const login = await neteaseLogin(body.phone, body.code);
      if (!login.ok) return json({ message: login.msg }, 400);
      const song = await resolveSong(body.link);
      if (!song.ok) return json({ message: song.msg }, 400);
      const expQ = parseExpInput(body.exp);
      if (!expQ.ok) return json({ message: '有效期格式不对：填天数(如730)、日期(2028-10-18)或不填（默认2年）' }, 400);
      const r = await addEntry({ ck: 'MUSIC_U=' + login.musicU, song: song.song, added: beijingDate(), name: body.phone, uid: login.uid, email: email, grp: isG2 ? 2 : 1, exp: expQ.exp });
      if (!r.ok) return json({ message: r.msg }, 400);
      return json({ message: '登记成功，次日生效。' });
    }
    if (url.pathname === '/api/join_manual' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      const gp2 = groupPassCheck(c, body);
      if (!gp2.ok) return json({ message: gp2.msg }, gp2.status);
      // 号池满员闸口（与方式一同一把闸，防止走手动登记绕过）；一律按一群计数
      const isG2 = false;
      const myLimit = groupLimitOf(c, isG2);
      const _m2 = await mergePool();
      const grpUsed = _m2.length;   // 同方式一：本池行数即本群人数（D1 无 grp 列，原口径恒 0）
      if (grpUsed >= myLimit) return json({ message: '本群名额已满（上限 ' + myLimit + ' 人），暂停登记。已有账号的互听和签到不受影响，请稍后再试或联系群主。' }, 429);
      const mu = (body.musicU || '').trim();
      if (!mu) return json({ message: '请填写 MUSIC_U' }, 400);
      const email = (body.email || '').trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ message: '请填写常用邮箱' }, 400);
      const v = await validateCookie(mu);
      if (!v.ok) return json({ message: v.msg }, 400);
      const song = await resolveSong(body.link);
      if (!song.ok) return json({ message: song.msg }, 400);
      const expQ = parseExpInput(body.exp);
      if (!expQ.ok) return json({ message: '有效期格式不对：填天数(如730)、日期(2028-10-18)或不填（默认2年）' }, 400);
      const phoneRaw = (body.phone || '').replace(/[^0-9]/g, '');
      const phone = /^1\d{10}$/.test(phoneRaw) ? phoneRaw : '';
      const r = await addEntry({ ck: 'MUSIC_U=' + mu, song: song.song, added: beijingDate(), name: phone || ('manual:' + v.uid), uid: v.uid, email: email, phone: phone, grp: isG2 ? 2 : 1, exp: expQ.exp });
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
      if (!c.groupPass || body.pass !== c.groupPass) return json({ message: '群口令错误' }, 403);
      let master = await mergePool();
      await pushPool(master, true);   // 强制推：resync 就是「现在就要一份全量快照到 Secrets」
      return json({ message: `已从 KV 重新同步 ${master.length} 条到 GitHub Secrets（NB_POOL_1..${12}）。` });
    }
    // 失效账号清理：Actions 跑完发现 cookie 失效的号，按 name/uid 从号池剔除并重写分片
    if (url.pathname === '/api/report_dead' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.groupPass || body.pass !== c.groupPass) return json({ message: '群口令错误' }, 403);
      const deadSet = new Set((body.dead || []).map(x => String(x)));
      if (!deadSet.size) return json({ message: '没有需要清理的账号。' });
      const master = await mergePool();
      const before = master.length;
      const deadEntries = master.filter(e => deadSet.has(String(e.name)) || deadSet.has(String(e.uid)));
      if (!deadEntries.length) return json({ message: `没有匹配到账号（号池 ${before} 个）。` });

      // ---- 死号双重确认（2026-10-22）----
      // 网易风控/限流时会出现「code 200 但 profile 缺失、每日推荐 0 首」，一次判定就把活号
      // 永久删掉，号主得重新登记。改为：第一次判死只打标 suspect_at；隔 18~36 小时
      // （即紧接着的下一轮）再次判死才真删。窗口外（同一天重复上报 / 太久以前的旧记录）
      // 一律重新打标，避免「一个月前疑似过」被当成今天的确诊。
      const susRows = await d1All('SELECT uid,suspect_at FROM accounts WHERE pool=?', [POOL_NAME]);
      const susMap = {};
      if (susRows) for (const r of susRows) susMap[String(r.uid)] = String(r.suspect_at || '');
      const nowMs = Date.now();
      const suspects = [], confirmed = [];
      for (const e of deadEntries) {
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
      return json({ message: `本次确认清理 ${confirmed.length} 个${confirmed.length ? '（' + nm(confirmed) + '）' : ''}；`
        + `新增疑似 ${suspects.length} 个（需下一轮再次判死才删除${suspects.length ? '：' + nm(suspects) : ''}），`
        + `剩余 ${after.length} 个。` });
    }
    // ====================================================================
    // 进阶控制台（2026-10-22 新增，全部为纯新增路由，不改动任何既有路由）
    // 页面 /console；数据流：两群 run.py 播完顺带查工作台 → POST /api/snap 归口本 worker KV
    //（key: snap:<日期>:<pool>:<分片>，90 天过期）→ 控制台按日期聚合展示 + 日环比 + 编辑。
    // 登录：账号/密码均 xx1031（可在 KV 加 CONSOLE_PASS 键覆盖默认密码；用户名固定 xx1031）。
    // ====================================================================
    if (url.pathname === '/console' && request.method === 'GET') {
      return new Response(CONSOLE_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (url.pathname === '/api/console/login' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const ok = await consoleAuth(body);
      return json(ok ? { ok: true } : { ok: false, message: '账号或密码错误' }, ok ? 200 : 403, CORS);
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
      if (!(await consoleAuth(body))) return json({ message: '账号或密码错误' }, 403, CORS);
      const date = /^\d{4}-\d{2}-\d{2}$/.test(body.date || '') ? body.date : beijingDate();
      const prevDate = dateMinus1(date);
      // 2026-10-22：控制台是高频只读接口，原来每刷新一次就跑 pruneExpired()（全量重建 +
      // 可能删键 + 写 204KB master + 推 12 个 Secret）。改为直接读 D1 全表（一条 SELECT）。
      // 过期号在页面上仍会按 exp 字段标红，真正的清理交给管理后台/resync。
      const master = await mergePool();
      const disp = e => ({
        name: e.name || '', uid: e.uid != null ? String(e.uid) : '',
        song: e.song != null ? String(e.song) : '', added: e.added || '',
        email: e.email || '', phone: e.phone || '', noListen: !!e.noListen, exp: e.exp || '',
      });
      const hz = master.map(disp);
      // 定制群账号列表：实时向对端 worker 拉（对穿口令；拉失败不阻塞主群展示）
      // ⚠️ 对穿方向：本 worker 的 PEER_PASS 键存的是「定制群口令」，而定制群 worker 的 PEER_PASS 键
      //    存的是「本群口令」——所以调对端接口要用本群群口令 c.groupPass，不是本 worker 的 PEER_PASS。
      let dz = [];
      try {
        const c2 = await cfg();
        const peerUrl = cleanKV(await POOL.get('PEER_URL')) || 'https://dz.xx1031.xyz';
        if (c2.groupPass) {
          const r = await fetch(peerUrl.replace(/\/+$/, '') + '/api/peer/pool?pass=' + encodeURIComponent(c2.groupPass), { headers: { 'User-Agent': 'cron-relay-worker' } });
          const d = await r.json();
          if (d && d.ok) dz = (d.entries || []).map(disp);
        }
      } catch (e) { /* 对端不可达：dz 列表留空，页面会提示 */ }
      const cur = await readSnapDay(date);
      const prev = await readSnapDay(prevDate);
      // 2026-10-22 第三批：D1 可用时不再读 KV 的 console:durs（省一次读，也不会读到旧值）。
      // 只有 D1 不可用时才回退 KV —— 那份现在已经只在 D1 写失败时才会被更新。
      let durs = {};
      const dr = d1ok() ? await d1All('SELECT uid,dur FROM durs') : null;
      if (dr) {
        for (const r of dr) { if (r.uid && r.dur != null) durs[String(r.uid)] = Number(r.dur) || 0; }
      } else {
        try { durs = JSON.parse(await POOL.get('console:durs') || '{}'); } catch (e) {}
      }
      return json({ ok: true, date: date, prevDate: prevDate, hz: hz, dz: dz, durs: durs, snap: { cur: cur, prev: prev } }, 200, CORS);
    }
    // 控制台编辑：hz 本地执行（与管理后台同一套逻辑）；dz 转发到对端 worker 的对等接口
    if (url.pathname === '/api/console/entry' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuth(body))) return json({ message: '账号或密码错误' }, 403, CORS);
      if (body.pool === 'dz') {
        try {
          const c3 = await cfg();
          // 对穿方向见 /api/console/data 处注释：调对端要用本群群口令（对端 PEER_PASS 键里存的就是它）
          const peerUrl = (cleanKV(await POOL.get('PEER_URL')) || 'https://dz.xx1031.xyz').replace(/\/+$/, '');
          if (!c3.groupPass) return json({ message: '本 worker 未配置群口令（KV 键 GROUP_PASS），无法编辑定制群账号' }, 503, CORS);
          const fwd = { pass: c3.groupPass, action: body.action, uid: body.uid, name: body.name,
            ck: body.ck, link: body.link, email: body.email, exp: body.exp, noListen: body.noListen };
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
    return json({ message: 'not found' }, 404);
}

function json(o, status = 200, extraHeaders) { return new Response(JSON.stringify(o), { status, headers: Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {}) }); }

// ---- 控制台登录校验（2026-10-22）：用户名固定 xx1031；密码只认 KV 键 CONSOLE_PASS ----
// 2026-10-22 安全修正：原先未配置 CONSOLE_PASS 时回落到缺省口令 xx1031，等于控制台对外敞开
//（实测匿名可登录、可看全池姓名/uid/邮箱、可删任意账号）。现在未配置 = 不开放，必须显式设置。
async function consoleAuth(body) {
  const u = String((body && body.user) || ''), p = String((body && body.pass) || '');
  if (u !== 'xx1031') return false;
  const expect = cleanKV(await POOL.get('CONSOLE_PASS'));
  if (!expect) return false;
  return p === expect;
}
// ---- 读一天的快照：聚合 snap:<date>:<pool>:<分片> 所有键 → { hz: {uid: acc}, dz: {uid: acc} } ----
async function readSnapDay(date) {
  const out = { hz: {}, dz: {} };
  // 2026-10-22：快照改读 D1 snapshots 表。原来是 list 一次 + 每个分片一次 get，
  // 且 list 走 KV 配额；现在一条 SELECT 就拿到当天全部号。
  if (d1ok()) {
    const rows = await d1All('SELECT pool,uid,rate,rpc30,cnt,missions,dur FROM snapshots WHERE day=?', [date]);
    if (rows) {
      for (const r of rows) {
        const pool = r.pool === 'dz' ? 'dz' : 'hz';
        let mis = {};
        try { mis = r.missions ? JSON.parse(r.missions) : {}; } catch (e) {}
        const acc = { rate: r.rate == null ? null : Number(r.rate), rpc30: r.rpc30 == null ? null : Number(r.rpc30),
                      cnt: r.cnt == null ? null : Number(r.cnt), mis: mis || {},
                      dur: r.dur == null ? null : Number(r.dur) };
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
      else if (/^\d{1,3}$/.test(x)) { const d = beijingDatePlus(parseInt(x, 10)); target.exp = d; changes.push('有效期=' + x + '天(' + d + '止)'); }
      else return json({ message: '有效期格式不对：填天数(如30)、日期(2026-12-31)或"永久"' }, 400, CORS);
    }
    if (body.noListen !== undefined && body.noListen !== null) {
      target.noListen = !!body.noListen;
      changes.push(body.noListen ? '暂停互听(只收不听)' : '恢复互听');
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

const INDEX_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>成员接入</title><style>body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;padding:24px 12px;display:flex;flex-direction:column;align-items:center;gap:16px}.head{text-align:center;margin-bottom:2px}.page-title{font-size:20px;font-weight:600;color:#3b6d11;margin:0}.page-sub{font-size:13px;color:#666;margin:6px 0 0}.wrap{display:flex;flex-wrap:wrap;gap:18px;justify-content:center;width:100%;max-width:1060px}.card{background:#fff;padding:26px 22px;border-radius:14px;width:330px;min-width:0;box-sizing:border-box;box-shadow:0 2px 12px rgba(0,0,0,.08)}h1{font-size:17px;margin:0 0 4px}h1.alt{color:#b06a00}p{font-size:13px;color:#666;margin:0 0 16px;line-height:1.5}label{display:block;font-size:13px;margin:12px 0 4px;color:#333}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ddd;border-radius:8px;font-size:14px}.row{display:flex;gap:8px}.row input{flex:1}button{margin-top:14px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:15px;cursor:pointer}button.mini{margin-top:0;width:auto;padding:10px 12px;font-size:13px;background:#5a8f1d;white-space:nowrap}button:disabled{opacity:.55;cursor:default}.msg{margin-top:14px;font-size:13px;min-height:18px;line-height:1.5}.ok{color:#3b6d11}.err{color:#a32d2d}.tip{color:#666}details{margin-top:14px;font-size:12px;color:#666;line-height:1.6}summary{cursor:pointer;color:#3b6d11}code{background:#eee;padding:1px 4px;border-radius:4px}.admin-entry{margin:10px 0 0;font-size:12px}.admin-entry a{color:#3b6d11;text-decoration:none;border-bottom:1px dashed #3b6d11;padding-bottom:1px}.abox{background:#fff;padding:22px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:1060px;box-sizing:border-box}.stats{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px}.stat{flex:1;min-width:100px;background:#f2f7ea;border-radius:10px;padding:10px 12px;text-align:center}.stat b{display:block;font-size:20px;color:#3b6d11}.stat span{font-size:12px;color:#666}.stat.warn b{color:#b06a00}.stat.warn{background:#fdf3e3}.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}.tools input{flex:1;min-width:160px;padding:9px 10px;border:1px solid #ddd;border-radius:8px;font-size:14px}.tools button{margin-top:0;width:auto;padding:9px 14px;font-size:13px}button.gray{background:#888}.twrap{overflow-x:auto;border:1px solid #eee;border-radius:10px}table{border-collapse:collapse;width:100%;font-size:13px}th{background:#f5f6f8;text-align:left;padding:9px 10px;white-space:nowrap;color:#444;border-bottom:1px solid #eee}td{padding:8px 10px;border-bottom:1px solid #f2f2f2;white-space:nowrap}tr:hover td{background:#fafdf5}.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:8px;margin-right:4px}.b-red{background:#fbe4e4;color:#a32d2d}.b-gray{background:#eee;color:#666}.b-yellow{background:#fdf3e3;color:#b06a00}.num{font-family:ui-monospace,Consolas,monospace;color:#555}</style></head><body><div class="head"><h1 class="page-title">成员接入</h1><p class="page-sub">上方两种方式登记新账号；已经登记过的成员，可在下方补录或修改通知邮箱（页面版本 v20261020a）</p></div><div class="wrap"><div class="card"><h1>成员接入（方式一 · 手机登录）</h1><p>① 填手机号 → ② 填邮箱 → ③ 点「获取验证码」收短信 → ④ 填验证码和歌曲链接 → ⑤ 点登记。系统自动登录并登记，<b>次日生效</b>。邮箱用于接收账号提醒：账号需要完成一次验证、或登录过期时，会发邮件到这个邮箱通知你。注意：<b>每个账号限登记一首歌</b>，重复登记会被拒绝；<b>号池上限 __POOL_LIMIT__ 人</b>，满员后暂停登记。<b>若提示短信发送失败（网易限制机房 IP，属正常现象），请直接用下方方式二。</b></p><label>手机号</label><input id="phone" inputmode="numeric" maxlength="11" placeholder="11 位手机号"><label>短信验证码</label><div class="row"><input id="code" inputmode="numeric" maxlength="6" placeholder="网易云短信验证码"><button id="send" class="mini">获取验证码</button></div><label>分享链接</label><input id="link" placeholder="粘贴 APP 内分享的单曲链接"><label>邮箱（必填）</label><input id="email" type="text" placeholder="账号有变化时邮件通知你"><button id="btn">登录并登记</button><div class="msg tip" id="msg">提示：只支持【单曲】链接，歌单/专辑会被拒绝。链接在网易云 APP 里「分享→复制链接」即可。</div></div><div class="card"><h1 class="alt">成员接入（方式二 · 推荐）</h1><p>最稳的登记方式：自己从浏览器复制 <code>MUSIC_U</code> 粘贴过来，同样<b>次日生效</b>。<b>每个账号限登记一首歌</b>，重复登记会被拒绝。</p><label>MUSIC_U</label><input id="mu" placeholder="粘贴浏览器里的 MUSIC_U 值"><label>分享链接</label><input id="link2" placeholder="粘贴 APP 内分享的单曲链接"><label>邮箱（必填）</label><input id="email2" type="text" placeholder="账号有变化时邮件通知你"><button id="btn2">直接登记</button><details><summary>怎么拿到 MUSIC_U？（点开看）</summary>用电脑浏览器打开 <code>https://music.163.com</code> 并登录 → 按 <code>F12</code> → 切到「Application / 应用」标签 → 左侧展开 <code>Cookies</code> → 选 <code>music.163.com</code> → 在右边找到名为 <code>MUSIC_U</code> 的那一行，复制它的「Value / 值」整串粘进来即可。</details><div class="msg tip" id="msg2"></div></div><div class="card"><h1 class="alt">绑定 / 更换通知邮箱</h1><p>之前登记时没填邮箱、或者想换一个邮箱，在这里改一下就行。<b>只改邮箱，其他设置原样不动</b>，之后想再换随时能来改。账号有变化时（比如需要完成一次验证、登录过期），会发邮件到这个邮箱提醒你。</p><label>手机号（方式一登记的填这个）</label><input id="pm_phone" inputmode="numeric" maxlength="11" placeholder="登记时用的 11 位手机号"><label>MUSIC_U（方式二登记的填这个，与手机号二选一即可）</label><input id="pm_mu" placeholder="方式二登记时粘贴的 MUSIC_U"><label>常用邮箱</label><input id="pm_email" type="text" placeholder="name@qq.com"><button id="btn3">保存邮箱</button><div class="msg tip" id="msg3">手机号和 MUSIC_U 填其中一个就行。</div></div></div><script>const $=id=>document.getElementById(id);function normPhone(s){return (s||'').replace(/[０-９]/g,c=>String.fromCharCode(c.charCodeAt(0)-65248)).replace(/[^0-9]/g,'');}function setMsg(el,t,cls){const m=$(el);m.textContent=t;m.className='msg'+(cls?(' '+cls):'');}let timer=null;$('send').onclick=async()=>{const phone=normPhone($('phone').value);if(!/^1[0-9]{10}$/.test(phone)){setMsg('msg','手机号格式不对：识别到 '+phone.length+' 位（'+phone+'）。若带了 +86 前缀请删掉，只填 11 位号码','err');return;}$('send').disabled=true;setMsg('msg','正在发送验证码…');try{const r=await fetch('/api/sendcode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone})});const d=await r.json();if(r.ok){setMsg('msg','验证码已发送，请查收短信','ok');startCd();}else{setMsg('msg',d.message||'发送失败，请重试','err');$('send').disabled=false;}}catch(e){setMsg('msg','网络错误，请重试','err');$('send').disabled=false;}};function startCd(){let cd=60;$('send').textContent=cd+'s';timer=setInterval(()=>{cd--;if(cd<=0){clearInterval(timer);timer=null;$('send').textContent='获取验证码';$('send').disabled=false;}else{$('send').textContent=cd+'s';}},1000);}$('btn').onclick=async()=>{const phone=normPhone($('phone').value),code=$('code').value.trim(),link=$('link').value.trim(),email=$('email').value.trim();if(!/^1[0-9]{10}$/.test(phone)){setMsg('msg','手机号格式不对','err');return;}if(!/^[0-9]{4,6}$/.test(code)){setMsg('msg','请填写验证码','err');return;}if(!link){setMsg('msg','请填写歌曲链接','err');return;}if(!email){setMsg('msg','请填写邮箱（用于接收任务验证码与异常提醒）','err');return;}setMsg('msg','处理中…');$('btn').disabled=true;try{const r=await fetch('/api/join',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone,code,link,email})});const d=await r.json();if(r.ok){setMsg('msg',d.message||'登记成功，次日开始。','ok');}else{setMsg('msg',d.message||'失败','err');}}catch(e){setMsg('msg','网络错误','err');}$('btn').disabled=false;};$('btn2').onclick=async()=>{const musicU=$('mu').value.trim(),link=$('link2').value.trim(),email=$('email2').value.trim();if(!musicU){setMsg('msg2','请填写 MUSIC_U','err');return;}if(!email){setMsg('msg2','请填写邮箱（用于接收任务验证码与异常提醒）','err');return;}if(!link){setMsg('msg2','请填写歌曲链接','err');return;}setMsg('msg2','处理中…');$('btn2').disabled=true;try{const r=await fetch('/api/join_manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({musicU,link,email})});const d=await r.json();if(r.ok){setMsg('msg2',d.message||'登记成功，次日开始。','ok');}else{setMsg('msg2',d.message||'失败','err');}}catch(e){setMsg('msg2','网络错误','err');}$('btn2').disabled=false;};$('btn3').onclick=async()=>{const phone=normPhone($('pm_phone').value),mu=$('pm_mu').value.trim(),email=$('pm_email').value.trim();if(!phone&&!mu){setMsg('msg3','手机号和 MUSIC_U 至少填一个（方式二登记的填 MUSIC_U）','err');return;}if(!email){setMsg('msg3','请填写常用邮箱','err');return;}setMsg('msg3','正在保存…');$('btn3').disabled=true;try{const r=await fetch('/api/updatemail',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone,mu,email})});const d=await r.json();if(r.ok){setMsg('msg3',d.message||'已保存','ok');}else{setMsg('msg3',d.message||'保存失败','err');}}catch(e){setMsg('msg3','网络错误','err');}$('btn3').disabled=false;};</script><script>(function(){var re=/(登录失败|短信发送失败)/,done=false;function fire(){if(done)return;done=true;var mu=document.getElementById('mu');if(mu){var c=mu.closest('.card');if(c){c.style.outline='2px solid #b06a00';c.scrollIntoView({behavior:'smooth',block:'center'});}}var ds=document.querySelectorAll('details');for(var i=0;i<ds.length;i++){try{ds[i].open=true;}catch(e){}}var m=document.getElementById('msg2');if(m){m.textContent='⚠️ 方法一被网易风控拦截（如 8860），请改用下方方法二：先登录 music.163.com，再按说明复制 MUSIC_U 粘贴到输入框';m.className='msg err';}}try{new MutationObserver(function(){document.querySelectorAll('.msg').forEach(function(el){if(re.test(el.textContent||''))fire();});}).observe(document.body,{subtree:true,childList:true,characterData:true});}catch(e){}})();</script></body></html>`;
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
  var rows=[['序号','账号','UID','歌曲ID','入池日期','邮箱','标记']];
  POOL.forEach(function(e,i){rows.push([i+1,e.name,e.uid||'',e.song||'',e.added||'',e.email||'',e.marks||'']);});
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
   +'<div class="stat"><b>'+(STATS.limit||1500)+'</b><span>人数上限</span></div>'
   +'<div class="stat'+(STATS.remain<=20?' warn':'')+'"><b>'+STATS.remain+'</b><span>剩余名额</span></div>'
   +'<div class="stat"><b>'+(list.length)+'</b><span>当前筛选</span></div>';
  var h='';
  list.forEach(function(e,i){
    var song=e.song?'<a class="song" target="_blank" href="https://music.163.com/song?id='+e.song+'">'+e.song+'</a>':'<span style="color:#bbb">—</span>';
    h+='<tr><td class="num">'+(i+1)+'</td><td>'+esc(e.name)+'</td><td class="num">'+esc(e.uid)+'</td><td class="num">'+song+'</td><td class="num">'+esc(e.added)+'</td><td>'+esc(e.email||'—')+'</td><td>'+badges(e)+'</td></tr>';
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
.abox{background:#fff;padding:20px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:1280px;box-sizing:border-box;margin:0 auto 14px}
input,select{padding:9px 10px;border:1px solid #ddd;border-radius:8px;font-size:13px;box-sizing:border-box}
button{padding:9px 14px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:13px;cursor:pointer}
button.gray{background:#888}button.warn{background:#a32d2d}button:disabled{opacity:.55;cursor:default}
.msg{font-size:13px;min-height:16px;margin-top:8px}.ok{color:#3b6d11}.err{color:#a32d2d}
.stats{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.stat{flex:1;min-width:96px;background:#f2f7ea;border-radius:10px;padding:8px 10px;text-align:center}
.stat b{display:block;font-size:19px;color:#3b6d11}.stat span{font-size:11px;color:#666}
.stat.warn{background:#fdf3e3}.stat.warn b{color:#b06a00}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.tools input{min-width:130px}.tools input#q{flex:1;min-width:160px}
.tab{padding:8px 14px;border-radius:8px;background:#eee;color:#555;cursor:pointer;font-size:13px}
.tab.on{background:#3b6d11;color:#fff}
.twrap{overflow-x:auto;border:1px solid #eee;border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:12.5px;white-space:nowrap}
th{background:#f5f6f8;text-align:left;padding:8px 9px;color:#444;border-bottom:1px solid #eee;position:sticky;top:0}
td{padding:7px 9px;border-bottom:1px solid #f2f2f2}
tr:hover td{background:#fafdf5}
.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:8px;margin-right:3px}
.b-hz{background:#e8f2df;color:#3b6d11}.b-dz{background:#e3ecf7;color:#2d5aa3}
.b-red{background:#fbe4e4;color:#a32d2d}.b-gray{background:#eee;color:#666}.b-yellow{background:#fdf3e3;color:#b06a00}
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
</style></head><body>
<div class="head"><h1 class="page-title">650 任务进阶控制台</h1><p class="page-sub">两群账号每日快照 · 数据由 Actions 播放时段顺带采集（T+1 可见）· CK 不在页面展示</p></div>
<div class="abox" id="loginBox">
  <h3 style="margin:0 0 10px">登录</h3>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <input id="lu" placeholder="账号" style="flex:1;min-width:140px">
    <input id="lp" type="password" placeholder="密码" style="flex:1;min-width:140px">
    <button id="lbtn">进入</button>
  </div>
  <div class="msg" id="lm"></div>
</div>
<div class="abox" id="mainBox" hidden>
  <div class="stats" id="stats"></div>
  <div class="tools">
    <span class="tab on" data-p="all">全部</span><span class="tab" data-p="hz">主群</span><span class="tab" data-p="dz">定制群</span>
    <input type="date" id="date">
    <input id="q" placeholder="搜索：账号 / 邮箱 / UID / 歌曲ID">
    <select id="sort"><option value="default">排序：默认</option><option value="delta">排序：日涨幅↓</option><option value="rate">排序：今日rate↓</option></select>
    <button class="mini" id="btnCsv">导出CSV</button>
    <button class="mini" id="btnRefresh">刷新</button>
    <button class="mini gray" id="btnOut">退出</button>
  </div>
  <div class="twrap"><table><thead><tr>
    <th>#</th><th>池</th><th>账号</th><th>UID</th><th>绑定歌曲</th><th>时长</th><th>昨rate</th><th>今rate</th><th>日环比</th><th>rpc30</th><th>任务</th><th>入池</th><th>有效期</th><th>标记</th><th>操作</th>
  </tr></thead><tbody id="tb"></tbody></table></div>
  <p style="font-size:12px;color:#888;margin:10px 0 0">数据口径：rate=音乐人后台 650 任务进度（近30日滚动累计，会回吐）；rpc30=近30日有效播放次数；任务列=工作台子任务进度；日环比=今日快照-昨日快照；时长=登记歌曲长度（红=短歌&lt;2:12、黄=长歌&gt;5:36，历史上这两类曾被时长Bug卡过有效播放，10-22 已修复）。</p>
</div>
<div class="modal" id="modal" hidden><div class="mbox">
  <h3 id="mTitle">编辑账号</h3><p style="font-size:12px;color:#888;margin:4px 0 0" id="mSub"></p>
  <label>改绑歌曲（粘贴 APP 分享链接，留空不改）</label><input id="eLink" placeholder="https://163.com/... 或 song?id=...">
  <label>通知邮箱（留空不改）</label><input id="eEmail">
  <label>有效期（天数 / 日期 / 永久，留空不改）</label><input id="eExp">
  <label>暂停互听（只收不听）</label><select id="eNo"><option value="">不修改</option><option value="0">参与互听</option><option value="1">暂停互听</option></select>
  <label>更换 CK（MUSIC_U，留空不改；保存前服务端会先校验有效性）</label><input id="eCk" placeholder="粘贴新的 MUSIC_U 值">
  <div class="row2"><button id="eSave">保存修改</button><button class="warn" id="eDel">删除账号</button><button class="gray" id="eCancel">关闭</button></div>
  <div class="msg" id="em"></div>
</div></div>
<script>
var TOKEN=null, DATA=null, POOLF='all';
function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function todayBJ(){var d=new Date(Date.now()+8*3600*1000);return d.toISOString().slice(0,10);}
function api(ep,body){return fetch(ep,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});});}
function save(t){try{sessionStorage.setItem('consToken',t);}catch(e){}}
function load(){try{return sessionStorage.getItem('consToken');}catch(e){return null;}}
function login(){
  var u=$('lu').value.trim(),p=$('lp').value;
  if(!u||!p){$('lm').textContent='请输入账号和密码';$('lm').className='msg err';return;}
  $('lbtn').disabled=true;
  api('/api/console/login',{user:u,pass:p}).then(function(o){
    $('lbtn').disabled=false;
    if(o.ok&&o.d.ok){TOKEN=JSON.stringify({user:u,pass:p});save(TOKEN);$('loginBox').hidden=true;$('mainBox').hidden=false;loadData();}
    else{$('lm').textContent=(o.d&&o.d.message)||'登录失败';$('lm').className='msg err';}
  }).catch(function(){$('lbtn').disabled=false;$('lm').textContent='网络错误';$('lm').className='msg err';});
}
$('lbtn').onclick=login;
$('lp').onkeydown=function(e){if(e.key==='Enter')login();};
$('lu').onkeydown=function(e){if(e.key==='Enter')$('lp').focus();};
$('btnOut').onclick=function(){try{sessionStorage.removeItem('consToken');}catch(e){}location.reload();};
$('btnRefresh').onclick=loadData;
$('date').onchange=loadData;
$('q').oninput=render;$('sort').onchange=render;
document.querySelectorAll('.tab').forEach(function(t){t.onclick=function(){
  document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('on');});
  t.classList.add('on');POOLF=t.getAttribute('data-p');render();};});
function accsOf(day,pool){
  // 2026-10-23 修复：/api/console/data 返回的 snap 是 {cur:{hz,dz},prev:{hz,dz}}，
  // 这里原来按 snap[日期][池] 取 → 取不到，a/p 恒为 null，
  // 导致「昨rate / 今rate / 日环比 / rpc30 / 任务」五列全空、今日有数据恒为 0。
  var S=DATA.snap||{};
  if(S.cur||S.prev){var src=(day&&day===DATA.prevDate)?S.prev:S.cur;return (src&&src[pool])||{};}
  return (S[day]&&S[day][pool])||{};
}
function loadData(){
  var t=JSON.parse(TOKEN||'{}');
  $('btnRefresh').disabled=true;
  api('/api/console/data',{user:t.user,pass:t.pass,date:$('date').value||todayBJ()}).then(function(o){
    $('btnRefresh').disabled=false;
    if(!o.ok){$('lm').textContent=o.d.message||'请重新登录';$('lm').className='msg err';$('loginBox').hidden=false;$('mainBox').hidden=true;return;}
    DATA=o.d;$('date').value=DATA.date;render();
  }).catch(function(){$('btnRefresh').disabled=false;});
}
function buildRows(){
  if(!DATA)return[];
  var cur=DATA.snap.cur,prev=DATA.snap.prev,rows=[];
  [['hz',DATA.hz],['dz',DATA.dz]].forEach(function(pd){
    var pool=pd[0];
    pd[1].forEach(function(e){
      var a=accsOf(DATA.date,pool)[e.uid]||null,p=accsOf(DATA.prevDate,pool)[e.uid]||null;
      var delta=(a&&p&&a.rate!=null&&p.rate!=null)?(a.rate-p.rate):null;
      rows.push({pool:pool,e:e,a:a,p:p,delta:delta});
    });
  });
  return rows;
}
function render(){
  if(!DATA)return;
  var q=($('q').value||'').trim().toLowerCase();
  var rows=buildRows().filter(function(r){
    if(POOLF!=='all'&&r.pool!==POOLF)return false;
    if(!q)return true;
    var e=r.e;
    return ((e.name||'')+' '+(e.email||'')+' '+(e.uid||'')+' '+(e.song||'')).toLowerCase().indexOf(q)>=0;
  });
  var s=$('sort').value;
  if(s==='delta')rows.sort(function(x,y){return (y.delta==null?-999:y.delta)-(x.delta==null?-999:x.delta);});
  else if(s==='rate')rows.sort(function(x,y){return ((y.a&&y.a.rate)||-1)-((x.a&&x.a.rate)||-1);});
  var withData=rows.filter(function(r){return r.a;});
  var ups=rows.filter(function(r){return r.delta!=null&&r.delta>0;}).length;
  var downs=rows.filter(function(r){return r.delta!=null&&r.delta<0;}).length;
  var avg=withData.length?Math.round(withData.reduce(function(s,r){return s+(r.a.rate||0);},0)/withData.length):0;
  $('stats').innerHTML=
    '<div class="stat"><b>'+rows.length+'</b><span>账号总数</span></div>'
   +'<div class="stat"><b>'+withData.length+'</b><span>今日有数据</span></div>'
   +'<div class="stat"><b>'+avg+'%</b><span>平均rate</span></div>'
   +'<div class="stat"><b style="color:#c0392b">'+ups+'</b><span>上涨</span></div>'
   +'<div class="stat"><b style="color:#1e8449">'+downs+'</b><span>回吐/下跌</span></div>'
   +'<div class="stat'+(rows.length-withData.length?' warn':'')+'"><b>'+(rows.length-withData.length)+'</b><span>暂无快照</span></div>';
  var h='';
  rows.forEach(function(r,i){
    var e=r.e,a=r.a;
    var rateNow=a&&a.rate!=null?a.rate:'—',ratePrev=r.p&&r.p.rate!=null?r.p.rate:'—';
    var dCell=r.delta==null?'<span class="flat">—</span>':(r.delta>0?'<span class="up">+'+r.delta+'</span>':(r.delta<0?'<span class="down">'+r.delta+'</span>':'<span class="flat">0</span>'));
    var mis=a&&a.mis?Object.keys(a.mis).map(function(k){return k+' '+a.mis[k]+'%';}).join(' / '):'';
    var misCell=mis?'<span class="mission" title="'+esc(mis)+'">'+esc(mis)+'</span>':'<span class="flat">—</span>';
    var song=e.song?'<a class="song" target="_blank" href="https://music.163.com/song?id='+e.song+'">'+e.song+'</a>':'<span style="color:#bbb">公益</span>';
    var dur=(DATA.durs||{})[e.uid]||((a&&a.dur)||0);
    var durCell='<span class="flat">—</span>';
    if(dur>0){var mm=Math.floor(dur/60),ss=('0'+(dur%60)).slice(-2);
      durCell=dur<132?'<span class="badge b-red" title="短歌：历史上曾被时长Bug卡过有效播放，修复(10-22)后应正常">'+mm+':'+ss+'</span>'
        :(dur>336?'<span class="badge b-yellow" title="长歌：播放耗时长，拖慢单班进度">'+mm+':'+ss+'</span>'
        :'<span class="num">'+mm+':'+ss+'</span>');}
    var marks=(e.noListen?'<span class="badge b-red">只收</span>':'')+(!e.email?'<span class="badge b-yellow">无邮箱</span>':'')+(!a?'<span class="badge b-gray">无数据</span>':'');
    h+='<tr><td class="num">'+(i+1)+'</td>'
      +'<td><span class="badge '+(r.pool==='hz'?'b-hz">主群':'b-dz">定制')+'</span></td>'
      +'<td>'+esc(e.name)+'</td><td class="num">'+esc(e.uid)+'</td><td class="num">'+song+'</td><td>'+durCell+'</td>'
      +'<td class="num">'+ratePrev+'</td><td class="num" style="font-weight:600">'+rateNow+'</td><td>'+dCell+'</td>'
      +'<td class="num">'+(a&&a.rpc30!=null?a.rpc30:'—')+'</td><td>'+misCell+'</td>'
      +'<td class="num">'+esc(e.added)+'</td><td class="num">'+esc(e.exp||'永久')+'</td>'
      +'<td>'+(marks||'<span style="color:#bbb">正常</span>')+'</td>'
      +'<td><button class="mini" style="padding:4px 10px;font-size:12px" data-pool="'+r.pool+'" data-uid="'+esc(e.uid)+'" data-name="'+esc(e.name)+'">编辑</button></td></tr>';
  });
  $('tb').innerHTML=h||'<tr><td colspan="15" style="text-align:center;color:#999;padding:20px">没有匹配的账号</td></tr>';
}
window.openEdit=function(pool,uid,name){
  $('eLink').value='';$('eEmail').value='';$('eExp').value='';$('eNo').value='';$('eCk').value='';$('em').textContent='';
  $('mTitle').textContent='编辑账号 · '+(pool==='hz'?'主群':'定制群');
  $('mSub').textContent=name+(uid?' / uid '+uid:'');
  $('modal').hidden=false;
  $('eSave').onclick=function(){doEdit(pool,{uid:uid,name:name},'update');};
  $('eDel').onclick=function(){if(confirm('确定从'+(pool==='hz'?'主群':'定制群')+'删除账号 '+(name||uid)+'？此操作不可恢复！'))doEdit(pool,{uid:uid,name:name},'delete');};
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
  }
  $('eSave').disabled=true;$('eDel').disabled=true;
  api('/api/console/entry',body).then(function(o){
    $('eSave').disabled=false;$('eDel').disabled=false;
    if(o.ok&&o.d.ok){$('em').textContent=o.d.message||'已保存';$('em').className='msg ok';setTimeout(function(){$('modal').hidden=true;loadData();},900);}
    else{$('em').textContent=(o.d&&o.d.message)||'操作失败';$('em').className='msg err';}
  }).catch(function(){$('eSave').disabled=false;$('eDel').disabled=false;$('em').textContent='网络错误';$('em').className='msg err';});
}
$('eCancel').onclick=function(){$('modal').hidden=true;};
$('btnCsv').onclick=function(){
  var rows=[['池','账号','UID','歌曲ID','时长(秒)','昨rate','今rate','日环比','rpc30','入池','有效期','邮箱','标记']];
  buildRows().forEach(function(r){
    var e=r.e;
    var dur=(DATA.durs||{})[e.uid]||((r.a&&r.a.dur)||'');
    rows.push([r.pool==='hz'?'主群':'定制群',e.name,e.uid||'',e.song||'',dur,
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
  $('date').value=todayBJ();
  var t=load();
  if(t){TOKEN=t;$('loginBox').hidden=true;$('mainBox').hidden=false;loadData();return;}
  // 2026-10-22：#pw= 免密进入（CK助手/书签用）。hash 不发给服务器，登录成功/失败后都立即 replaceState 抹掉，
  // 地址栏与历史记录不留明文；直接访问 /console 不带 hash 时仍走正常账号密码登录。
  var m=(location.hash||'').match(/pw=([^&]+)/);
  if(m){
    var pw=m[1];try{pw=decodeURIComponent(pw);}catch(e){}
    var u='xx1031';
    $('lm').textContent='正在自动登录…';$('lm').className='msg';
    api('/api/console/login',{user:u,pass:pw}).then(function(o){
      history.replaceState(null,'',location.pathname+location.search);
      if(o.ok&&o.d.ok){
        TOKEN=JSON.stringify({user:u,pass:pw});save(TOKEN);
        $('loginBox').hidden=true;$('mainBox').hidden=false;loadData();
      }else{
        $('lm').textContent=(o.d&&o.d.message)||'免密登录失败，请手动输入账号密码';$('lm').className='msg err';
      }
    }).catch(function(){
      history.replaceState(null,'',location.pathname+location.search);
      $('lm').textContent='网络错误，请手动登录';$('lm').className='msg err';
    });
  }
})();
</script></body></html>`;

// 2026-10-22：D1 绑定只支持 ES Module 格式，故入口从 addEventListener 改为
// export default { fetch }。既有代码全部按 service-worker 时代的「绑定即全局变量」
// 写法（POOL.get / GH_OWNER ...），这里在每个请求开头把 env 挂到 globalThis，
// 一行代码都不用改旧的。绑定对同一 isolate 的所有请求完全相同，挂全局是安全的。
export default {
  async fetch(request, env) {
    globalThis.POOL = env.POOL;
    globalThis.GH_OWNER = env.GH_OWNER;
    globalThis.GH_REPO = env.GH_REPO;
    if (env.DB) globalThis.DB = env.DB;
    try {
      return await handle(request);
    } catch (e) {
      return new Response(JSON.stringify({ message: '服务器内部错误：' + ((e && e.message) || e) }),
        { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
    }
  }
};
