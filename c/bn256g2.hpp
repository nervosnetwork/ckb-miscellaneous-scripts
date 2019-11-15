#ifndef CKB_MISCELLANEOUS_SCRIPT_BN256G2_H_
#define CKB_MISCELLANEOUS_SCRIPT_BN256G2_H_

#include <intx/intx.hpp>

#ifndef assert
#define assert(x)
#endif  // assert

namespace ckb {

using uint256 = intx::uint256;

constexpr uint256 FIELD_MODULUS = intx::from_string<uint256>(
    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");

constexpr uint256 TWIST[2] = {
    intx::from_string<uint256>(
        "0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5"),
    intx::from_string<uint256>(
        "0x9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2")};

constexpr size_t IX = 0;
constexpr size_t IY = 1;
constexpr size_t IZ = 2;

inline uint256 addmod(const uint256& a, const uint256& b, const uint256& n) {
  return n != 0 ? intx::addmod(a, b, n) : 0;
}

inline uint256 submod(const uint256& a, const uint256& b, const uint256& n) {
  return ckb::addmod(a, n - b, n);
}

inline uint256 mulmod(const uint256& a, const uint256& b, const uint256& n) {
  return n != 0 ? intx::mulmod(a, b, n) : 0;
}

uint256 _mod_inv(const uint256& a, const uint256& n) {
  uint256 t = 0;
  uint256 newT = 1;
  uint256 r = n;
  uint256 newR = a;
  while (newR != 0) {
    uint256 q = r / newR;
    uint256 oldT = t;
    t = newT;
    newT = submod(oldT, ckb::mulmod(q, newT, n), n);
    uint256 oldR = r;
    r = newR;
    newR = oldR - q * newR;
  }
  return t;
}

void _fq2_mul(const uint256 x[2], const uint256 y[2], uint256 r[2]) {
  uint256 a = submod(ckb::mulmod(x[IX], y[IX], FIELD_MODULUS),
                     ckb::mulmod(x[IY], y[IY], FIELD_MODULUS), FIELD_MODULUS);
  uint256 b =
      ckb::addmod(ckb::mulmod(x[IX], y[IY], FIELD_MODULUS),
                  ckb::mulmod(x[IY], y[IX], FIELD_MODULUS), FIELD_MODULUS);
  r[IX] = a;
  r[IY] = b;
}

inline void _fq2_muc(const uint256 x[2], const uint256& c, uint256 r[2]) {
  uint256 a = ckb::mulmod(x[IX], c, FIELD_MODULUS);
  uint256 b = ckb::mulmod(x[IY], c, FIELD_MODULUS);
  r[IX] = a;
  r[IY] = b;
}

inline void _fq2_add(const uint256 x[2], const uint256 y[2], uint256 r[2]) {
  uint256 a = ckb::addmod(x[IX], y[IX], FIELD_MODULUS);
  uint256 b = ckb::addmod(x[IY], y[IY], FIELD_MODULUS);
  r[IX] = a;
  r[IY] = b;
}

inline void _fq2_sub(const uint256 x[2], const uint256 y[2], uint256 r[2]) {
  uint256 a = submod(x[IX], y[IX], FIELD_MODULUS);
  uint256 b = submod(x[IY], y[IY], FIELD_MODULUS);
  r[IX] = a;
  r[IY] = b;
}

void _fq2_inv(const uint256 p[2], uint256 r[2]) {
  uint256 inv = _mod_inv(
      ckb::addmod(ckb::mulmod(p[IY], p[IY], FIELD_MODULUS),
                  ckb::mulmod(p[IX], p[IX], FIELD_MODULUS), FIELD_MODULUS),
      FIELD_MODULUS);
  uint256 a = ckb::mulmod(p[IX], inv, FIELD_MODULUS);
  uint256 b = FIELD_MODULUS - ckb::mulmod(p[IY], inv, FIELD_MODULUS);
  r[IX] = a;
  r[IY] = b;
}

void _fq2_div(const uint256 x[2], const uint256 y[2], uint256 r[2]) {
  uint256 temp[2];
  _fq2_inv(y, temp);
  _fq2_mul(x, temp, r);
}

bool _is_on_curve(const uint256 p[2][2]) {
  uint256 yy[2], xxx[2];
  _fq2_mul(p[IY], p[IY], yy);
  _fq2_mul(p[IX], p[IX], xxx);
  _fq2_mul(xxx, p[IX], xxx);
  _fq2_sub(yy, xxx, yy);
  _fq2_sub(yy, TWIST, yy);
  return yy[IX] == 0 && yy[IY] == 0;
}

void _from_jacobian(const uint256 pt1[3][2], uint256 pt2[2][2]) {
  uint256 invz[2];
  _fq2_inv(pt1[IZ], invz);
  _fq2_mul(pt1[IX], invz, pt2[IX]);
  _fq2_mul(pt1[IY], invz, pt2[IY]);
}

void _ec_twist_double_jacobian(const uint256 pt1[3][2], uint256 pt2[3][2]) {
  uint256 temp1[3][2];
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 2; j++) {
      temp1[i][j] = pt1[i][j];
      pt2[i][j] = 0;
    }
  }
  _fq2_muc(temp1[IX], 3, pt2[IX]);
  _fq2_mul(pt2[IX], temp1[IX], pt2[IX]);
  _fq2_mul(temp1[IY], temp1[IZ], temp1[IZ]);
  _fq2_mul(temp1[IX], temp1[IY], pt2[IY]);
  _fq2_mul(pt2[IY], temp1[IZ], pt2[IY]);
  _fq2_mul(pt2[IX], pt2[IX], temp1[IX]);
  _fq2_muc(pt2[IY], 8, pt2[IZ]);
  _fq2_sub(temp1[IX], pt2[IZ], temp1[IX]);
  _fq2_mul(temp1[IZ], temp1[IZ], pt2[IZ]);
  _fq2_muc(pt2[IY], 4, pt2[IY]);
  _fq2_sub(pt2[IY], temp1[IX], pt2[IY]);
  _fq2_mul(pt2[IY], pt2[IX], pt2[IY]);
  _fq2_muc(temp1[IY], 8, pt2[IX]);
  _fq2_mul(pt2[IX], temp1[IY], pt2[IX]);
  _fq2_mul(pt2[IX], pt2[IZ], pt2[IX]);
  _fq2_sub(pt2[IY], pt2[IX], pt2[IY]);
  _fq2_muc(temp1[IX], 2, pt2[IX]);
  _fq2_mul(pt2[IX], temp1[IZ], pt2[IX]);
  _fq2_mul(temp1[IZ], pt2[IZ], pt2[IZ]);
  _fq2_muc(pt2[IZ], 8, pt2[IZ]);
}

void _ec_twist_add_jacobian(const uint256 pt1[3][2], const uint256 pt2[3][2],
                            uint256 pt3[3][2]) {
  if (pt1[IZ][IX] == 0 && pt1[IZ][IY] == 0) {
    for (int i = 0; i < 3; i++) {
      for (int j = 0; j < 2; j++) {
        pt3[i][j] = pt2[i][j];
      }
    }
    return;
  } else if (pt2[IZ][IX] == 0 && pt2[IZ][IY] == 0) {
    for (int i = 0; i < 3; i++) {
      for (int j = 0; j < 2; j++) {
        pt3[i][j] = pt1[i][j];
      }
    }
    return;
  }

  uint256 temp1[3][2], temp2[3][2];
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 2; j++) {
      temp1[i][j] = pt1[i][j];
      temp2[i][j] = pt2[i][j];
    }
  }

  _fq2_mul(temp2[IY], temp1[IZ], temp2[IY]);
  _fq2_mul(temp1[IY], temp2[IZ], pt3[IY]);
  _fq2_mul(temp2[IX], temp1[IZ], temp2[IX]);
  _fq2_mul(temp1[IX], temp2[IZ], pt3[IZ]);

  if (temp2[IX][IX] == pt3[IZ][IX] && temp2[IX][IY] == pt3[IZ][IY]) {
    if (temp2[IY][IX] == pt3[IY][IX] && temp2[IY][IY] == pt3[IY][IY]) {
      _ec_twist_double_jacobian(temp1, pt3);
      return;
    }

    pt3[IX][IX] = 1;
    pt3[IX][IY] = 0;
    pt3[IY][IX] = 1;
    pt3[IY][IY] = 0;
    pt3[IZ][IX] = 0;
    pt3[IZ][IY] = 0;
    return;
  }

  // W = z1 * z2
  _fq2_mul(temp1[IZ], temp2[IZ], temp2[IZ]);
  // U = U1 - U2
  _fq2_sub(temp2[IY], pt3[IY], temp1[IX]);
  // V = V1 - V2
  _fq2_sub(temp2[IX], pt3[IZ], temp1[IY]);
  // V_squared = V * V
  _fq2_mul(temp1[IY], temp1[IY], temp1[IZ]);
  // V_squared_times_V2 = V_squared * V2
  _fq2_mul(temp1[IZ], pt3[IZ], temp2[IY]);
  // V_cubed = V * V_squared
  _fq2_mul(temp1[IZ], temp1[IY], temp1[IZ]);
  // newz = V_cubed * W
  _fq2_mul(temp1[IZ], temp2[IZ], pt3[IZ]);
  // U * U
  _fq2_mul(temp1[IX], temp1[IX], temp2[IX]);
  // U * U * W
  _fq2_mul(temp2[IX], temp2[IZ], temp2[IX]);
  // U * U * U - V_cubed
  _fq2_sub(temp2[IX], temp1[IZ], temp2[IX]);
  // 2 * V_squared_times_V2
  _fq2_muc(temp2[IY], 2, temp2[IZ]);
  // A = U * U * W - V_cubed - 2 * V_squared_times_V2
  _fq2_sub(temp2[IX], temp2[IZ], temp2[IX]);
  // newx = V * A
  _fq2_mul(temp1[IY], temp2[IX], pt3[IX]);
  // V_squared_times_V2 - A
  _fq2_sub(temp2[IY], temp2[IX], temp1[IY]);
  // U * (V_squared_times_V2 - A)
  _fq2_mul(temp1[IX], temp1[IY], temp1[IY]);
  // V_cubed * U2
  _fq2_mul(temp1[IZ], pt3[IY], temp1[IX]);
  // newy = U * (V_squared_times_V2 - A) - V_cubed * U2
  _fq2_sub(temp1[IY], temp1[IX], pt3[IY]);
}

void _ec_twist_mul_jacobian(uint256 d, const uint256 pt1[3][2],
                            uint256 pt2[3][2]) {
  uint256 temp[3][2];
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 2; j++) {
      temp[i][j] = pt1[i][j];
    }
  }
  while (d != 0) {
    if ((d & 1) != 0) {
      _ec_twist_add_jacobian(pt2, temp, pt2);
    }
    _ec_twist_double_jacobian(temp, temp);
    d = d / 2;
  }
}

void ec_twist_add(const uint256 pt1[2][2], const uint256 pt2[2][2],
                  uint256 r[2][2]) {
  if (pt1[IX][IX] == 0 && pt1[IX][IY] == 0 && pt1[IY][IX] == 0 &&
      pt1[IY][IY] == 0) {
    if (!(pt2[IX][IX] == 0 && pt2[IX][IY] == 0 && pt2[IY][IX] == 0 &&
          pt2[IY][IY] == 0)) {
      assert(_is_on_curve(pt2));
    }
    for (int i = 0; i < 2; i++) {
      for (int j = 0; j < 2; j++) {
        r[i][j] = pt2[i][j];
      }
    }
    return;
  } else if (pt2[IX][IX] == 0 && pt2[IX][IY] == 0 && pt2[IY][IX] == 0 &&
             pt2[IY][IY] == 0) {
    assert(_is_on_curve(pt1));
    for (int i = 0; i < 2; i++) {
      for (int j = 0; j < 2; j++) {
        r[i][j] = pt1[i][j];
      }
    }
    return;
  }

  assert(_is_on_curve(pt1));
  assert(_is_on_curve(pt2));

  uint256 temp1[3][2], temp2[3][2], pt3[3][2];
  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      temp1[i][j] = pt1[i][j];
      temp2[i][j] = pt2[i][j];
    }
  }
  temp1[2][0] = 1;
  temp1[2][1] = 0;
  temp2[2][0] = 1;
  temp2[2][1] = 0;
  _ec_twist_add_jacobian(temp1, temp2, pt3);

  _from_jacobian(pt3, r);
}

void ec_twist_mul(const uint256& s, const uint256 pt1[2][2], uint256 r[2][2]) {
  uint256 temp[3][2];
  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      temp[i][j] = pt1[i][j];
    }
  }
  temp[IZ][IX] = 1;
  temp[IZ][IY] = 0;
  if (temp[IX][IX] == 0 && temp[IX][IY] == 0 && temp[IY][IX] == 0 &&
      temp[IY][IY] == 0) {
    temp[IX][IX] = 1;
    temp[IY][IX] = 1;
    temp[IZ][IX] = 0;
  } else {
    assert(_is_on_curve(temp));
  }

  uint256 pt2[3][2];
  _ec_twist_mul_jacobian(s, temp, pt2);

  _from_jacobian(pt2, r);
}

}  // namespace ckb

#endif /* CKB_MISCELLANEOUS_SCRIPT_BN256G2_H_ */
