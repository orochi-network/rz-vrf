use tiny_ec::{
    curve::{Affine, ECMultContext, Jacobian, Scalar},
    ECMULT_GEN_CONTEXT,
};
use tiny_keccak::{Hasher, Keccak};

/// Perform multiplication between a point and a scalar: a * P
pub fn ecmult(context: &ECMultContext, a: &Affine, na: &Scalar) -> Affine {
    let mut rj = Jacobian::default();
    context.ecmult(&mut rj, &Jacobian::from_ge(a), na, &Scalar::from_int(0));
    Affine::from(&rj)
}

pub fn hash_keccak256(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Hash point to Scalar
pub fn hash_points(
    g: &Affine,
    h: &Affine,
    pk: &Affine,
    gamma: &Affine,
    kg: &Affine,
    kh: &Affine,
) -> Scalar {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    let all_points = [g, h, pk, gamma, kg, kh];
    for point in all_points {
        hasher.update(point.x.b32().as_ref());
        hasher.update(point.y.b32().as_ref());
    }
    hasher.finalize(&mut output);
    Scalar::from(&output)
}

/// Hash to curve
pub fn hash_to_curve(alpha: &Scalar, y: Option<&Affine>) -> Affine {
    let mut r = Jacobian::default();
    ECMULT_GEN_CONTEXT.ecmult_gen(&mut r, alpha);
    match y {
        Some(v) => {
            r = r.add_ge(v);
            r
        }
        None => r,
    };
    Affine::from(&r)
}
