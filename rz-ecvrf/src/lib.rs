use helper::hash_keccak256;
use tiny_ec::{
    curve::{Affine, Jacobian, Scalar, AFFINE_G},
    PublicKey, ECMULT_CONTEXT,
};

/// EC-VRF proof
#[derive(Clone, Copy, Debug)]
pub struct R0ECVRF {
    pub public_key: PublicKey,
    /// gamma
    pub gamma: Affine,
    /// c
    pub c: Scalar,
    /// s
    pub s: Scalar,
    /// y is the result
    pub y: Scalar,
    // Seed of the proof
    pub alpha: Scalar,
}

impl R0ECVRF {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.public_key.serialize());
        buf.extend_from_slice(&self.gamma.x.b32());
        buf.extend_from_slice(&self.gamma.y.b32());
        buf.extend_from_slice(&self.c.b32());
        buf.extend_from_slice(&self.s.b32());
        buf.extend_from_slice(&self.y.b32());
        buf.extend_from_slice(&self.alpha.b32());
        buf
    }

    pub fn deserialize(data: &Vec<u8>) -> Self {
        let mut offset = 0;
        let public_key: PublicKey = PublicKey::parse_slice(
            &data[offset..offset + 65],
            Some(tiny_ec::PublicKeyFormat::Full),
        )
        .expect("Unable to parse public key");
        offset += 65;
        let gamma = Affine::from(&data[offset..offset + 64]);
        offset += 64;
        let c = Scalar::from(&data[offset..offset + 32]);
        offset += 32;
        let s = Scalar::from(&data[offset..offset + 32]);
        offset += 32;
        let y = Scalar::from(&data[offset..offset + 32]);
        offset += 32;
        let alpha = Scalar::from(&data[offset..offset + 32]);
        R0ECVRF {
            public_key,
            gamma,
            c,
            s,
            y,
            alpha,
        }
    }
}

mod helper;

use crate::helper::{ecmult, hash_points, hash_to_curve};

/// Ordinary verifier
pub fn verify(vrf_proof: &R0ECVRF) -> bool {
    let ctx_mul = &ECMULT_CONTEXT;
    let mut pub_affine: Affine = vrf_proof.public_key.into();
    pub_affine.x.normalize();
    pub_affine.y.normalize();

    assert!(pub_affine.is_valid_var());
    assert!(vrf_proof.gamma.is_valid_var());

    // H = ECVRF_hash_to_curve(alpha, pk)
    let h = hash_to_curve(&vrf_proof.alpha, Some(&pub_affine));
    let mut jh = Jacobian::default();
    jh.set_ge(&h);

    // U = c * pk + s * G
    //   = c * sk * G + (k - c * sk) * G
    //   = k * G
    let mut u = Jacobian::default();
    let pub_jacobian = Jacobian::from_ge(&pub_affine);
    ctx_mul.ecmult(&mut u, &pub_jacobian, &vrf_proof.c, &vrf_proof.s);

    // Gamma witness
    let witness_gamma = ecmult(ctx_mul, &vrf_proof.gamma, &vrf_proof.c);
    // Hash witness
    let witness_hash = ecmult(ctx_mul, &h, &vrf_proof.s);

    // V = c * gamma + s * H = witness_gamma + witness_hash
    //   = c * sk * H + (k - c * sk) * H
    //   = k *. H
    let v = Jacobian::from_ge(&witness_gamma).add_ge(&witness_hash);

    // c_prime = ECVRF_hash_points(G, H, pk, gamma, U, V)
    let computed_c = hash_points(
        &AFFINE_G,
        &h,
        &pub_affine,
        &vrf_proof.gamma,
        &Affine::from(&u),
        &Affine::from(&v),
    );

    // y = keccak256(gama.encode())
    let computed_y = Scalar::from(&hash_keccak256(
        <Affine as Into<[u8; 64]>>::into(vrf_proof.gamma).as_slice(),
    ));

    // computed values should equal to the real one
    computed_c.eq(&vrf_proof.c) && computed_y.eq(&vrf_proof.y)
}
