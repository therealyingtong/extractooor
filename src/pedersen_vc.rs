use std::{ops::{Mul, Add}, marker::PhantomData};

use ark_ec::{AffineRepr, VariableBaseMSM, ScalarMul, CurveGroup};
use ark_ff::{Field, FftField};
use rand::RngCore;

use crate::protocol::{self, PartialTranscript as _, Transcript as _};

#[derive(Clone, Debug)]
pub enum ProverMessage<G: AffineRepr> {
    /// open u
    Witness(G::ScalarField),
    /// (vl, vr)
    CrossTerms(G, G),
}

impl<G: AffineRepr> ProverMessage<G> {
    fn wtns(&self) -> G::ScalarField {
        match self {
            Self::Witness(u) => *u,
            _ => panic!(),
        }
    }

    fn cross_terms(&self) -> (G, G) {
        match self {
            Self::CrossTerms(vl, vr) => (*vl, *vr),
            _ => panic!(),
        }
    }
}

impl<G: AffineRepr> protocol::ProverMessage for ProverMessage<G> {}

#[derive(Clone, Debug)]
pub struct VerifierMessage<F: FftField>(F);
impl<F: FftField> protocol::VerifierMessage for VerifierMessage<F> {
    fn rand<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng))
    }
}

#[derive(Clone, Debug)]
struct PartialTranscript<G: AffineRepr> {
    round_index: usize,
    prover_messages: Vec<ProverMessage<G>>,
    verifier_messages: Vec<VerifierMessage<G::ScalarField>>,
}

impl<G: AffineRepr> Default for PartialTranscript<G> {
    fn default() -> Self {
        Self {
            round_index: 0,
            prover_messages: vec![],
            verifier_messages: vec![],
        }
    }
}

impl<G: AffineRepr> protocol::PartialTranscript for PartialTranscript<G> {
    type ProverMessage = ProverMessage<G>;
    type VerifierMessage = VerifierMessage<G::ScalarField>;

    fn round_index(&self) -> usize {
        self.round_index
    }
    fn prover_messages(&self) -> Vec<Self::ProverMessage> {
        self.prover_messages.clone()
    }
    fn verifier_messages(&self) -> Vec<Self::VerifierMessage> {
        self.verifier_messages.clone()
    }

    fn append_verifier_message(&self, verifier_message: Self::VerifierMessage) -> Self {
        let mut verifier_messages = self.verifier_messages.clone();
        verifier_messages.push(verifier_message);
        Self {
            round_index: self.round_index + 1,
            prover_messages: self.prover_messages.clone(),
            verifier_messages,
        }
    }

    fn append_prover_message(&self, prover_message: Self::ProverMessage) -> Self {
        let mut prover_messages = self.prover_messages.clone();
        prover_messages.push(prover_message);
        Self {
            round_index: self.round_index,
            prover_messages,
            verifier_messages: self.verifier_messages.clone(),
        }
    }
}


#[derive(Debug)]
struct Transcript<G: AffineRepr> {
    prover_messages: Vec<ProverMessage<G>>,
    verifier_messages: Vec<VerifierMessage<G::ScalarField>>,
}

impl<G: AffineRepr> protocol::Transcript for Transcript<G> {
    type ProverMessage = ProverMessage<G>;
    type VerifierMessage = VerifierMessage<G::ScalarField>;

    fn prover_messages(&self) -> Vec<Self::ProverMessage> {
        self.prover_messages.clone()
    }
    fn verifier_messages(&self) -> Vec<Self::VerifierMessage> {
        self.verifier_messages.clone()
    }
}

impl<G: AffineRepr> TryFrom<PartialTranscript<G>> for Transcript<G> {
    type Error = ();

    fn try_from(value: PartialTranscript<G>) -> Result<Self, Self::Error> {
        // FIXME check correctness

        Ok(Self {
            prover_messages: value.prover_messages,
            verifier_messages: value.verifier_messages,
        })
    }
}

#[derive(Clone)]
struct Prover<G: AffineRepr, const MU: usize> {
    u: Vec<G::ScalarField>,
    g: Vec<G>,
    c: G
}

impl<G: AffineRepr, const MU: usize> Prover<G, MU> {
    fn root_round<R: RngCore>(&self, rng: &mut R) -> ProverMessage<G> {
        println!("self.u in root_round: {:?}", self.u.len());
        println!("self.g in root_round: {:?}", self.g.len());

        let (vl, vr): (G::Group, G::Group) = compute_cross_terms(&self.u, &self.g);

        ProverMessage::CrossTerms(vl.into_affine(), vr.into_affine())
    }

    fn leaf_round(&self, tr: &PartialTranscript<G>) -> ProverMessage<G> {
        println!("self.u in leaf_round: {:?}", self.u.len());
        println!("self.g in leaf_round: {:?}", self.g.len());

        assert_eq!(self.u.len(), 2);

        ProverMessage::Witness(self.u[0])
    }

    fn next_folding_round(&mut self, alpha: G::ScalarField) -> ProverMessage<G> {
        println!("self.u in next_folding_round: {:?}", self.u.len());
        println!("self.g in next_folding_round: {:?}", self.g.len());

        self.u = fold_scalars(alpha, &self.u);
        self.g = fold_bases_affine(alpha, &self.g);

        let (vl, vr): (G::Group, G::Group) = compute_cross_terms(&self.u, &self.g);

        let alpha_sq = alpha * alpha;
        let alpha_sq_inv = alpha_sq.inverse().unwrap();

        self.c = (self.c + (vl * alpha_sq) + (vr * alpha_sq_inv)).into_affine();

        ProverMessage::CrossTerms(vl.into_affine(), vr.into_affine())
    }
}

impl<G: AffineRepr, const MU: usize> protocol::Prover for Prover<G, MU> {
    type Witness = Vec<G::ScalarField>;
    type ProverMessage = ProverMessage<G>;
    type PartialTranscript = PartialTranscript<G>;
    fn witness(&self) -> Self::Witness {
        self.u.clone()
    }

    fn next_round<R: RngCore>(
        &mut self,
        tr: &PartialTranscript<G>,
        rng: &mut R,
    ) -> Self::ProverMessage {
        if tr.round_index() == 0 {
            self.root_round(rng)
        } else if tr.round_index() == MU {
            self.leaf_round(&tr)
        } else {
            let alpha = tr.verifier_messages().last().unwrap().clone();
            self.next_folding_round(alpha.0)
        }
    }
}

#[derive(Clone)]
struct Verifier<G: AffineRepr> {
    /// Running commitment 
    c: G,
    /// Running basis
    g: Vec<G>
}

impl<G: AffineRepr> protocol::Verifier for Verifier<G> {
    type VerifierMessage = VerifierMessage<G::ScalarField>;
    type Instance = G::ScalarField;
    type Transcript = Transcript<G>;
    type PartialTranscript = PartialTranscript<G>;

    fn verify(&self, instance: &Self::Instance, tr: &Self::Transcript) -> bool {
        assert_eq!(self.g.len(), 1);
        let last_p_msg = tr.prover_messages().last().unwrap().clone().wtns();

        self.g[0] * *instance == self.c.into_group()
    }

    fn next_round<R: RngCore>(
        &mut self,
        tr: &PartialTranscript<G>,
        rng: &mut R,
    ) {
        if tr.round_index() == 0 {
            // we do nothing 
        } else if self.g.len() == 1 {
            // we do nothing 
        } else {
            let alpha = tr.verifier_messages().last().unwrap().clone().0;
            let (vl, vr) = tr.prover_messages().last().unwrap().clone().cross_terms();

            self.g = fold_bases_affine(alpha, &self.g);
    
            let alpha_sq = alpha * alpha;
            let alpha_sq_inv = alpha_sq.inverse().unwrap();
    
            self.c = (self.c + (vl * alpha_sq) + (vr * alpha_sq_inv)).into_affine();
        }
    }
}

struct Extractor<G: AffineRepr> {
    _marker: PhantomData<G>,
}

impl<G: AffineRepr> protocol::Extractor for Extractor<G> {
    type Witness = Vec<G::ScalarField>;
    type PartialTranscript = PartialTranscript<G>;

    fn extract(
        trs: &Vec<Self::PartialTranscript>,
        prev_extraction_witnesses: &Vec<Self::Witness>
    ) -> Self::Witness {
        assert_eq!(trs.len(), prev_extraction_witnesses.len());
        assert_eq!(trs.len(), 3);

        let alpha_1 = trs[0].verifier_messages().last().unwrap().clone().0;
        let alpha_2 = trs[1].verifier_messages().last().unwrap().clone().0;
        let alpha_3 = trs[2].verifier_messages().last().unwrap().clone().0;

        let (beta_1, beta_2, beta_3) = compute_betas(alpha_1, alpha_2, alpha_3);

        let extracted_u = extract(&prev_extraction_witnesses[0], &prev_extraction_witnesses[1], &prev_extraction_witnesses[2], alpha_1, alpha_2, alpha_3, beta_1, beta_2, beta_3);

        extracted_u
    }
}

pub fn pedersen<G: CurveGroup>(u: &[G::ScalarField], g: &[G::MulBase]) -> G {
    G::msm(g, u).unwrap()
}

pub fn compute_cross_terms<G: CurveGroup>(u: &[G::ScalarField], g: &[G::MulBase]) -> (G, G) {
    assert_eq!(u.len() % 2, 0);
    assert_eq!(g.len(), u.len());

    let half = u.len() / 2;

    let vl: G = pedersen(&u[..half], &g[half..]);
    let vr: G = pedersen(&u[half..], &g[..half]);

    (vl, vr)
}

pub fn fold_inner<F: Field, T: Copy + Mul<F, Output = T> + Add<T, Output = T>>(values: &[T], alpha: F) -> Vec<T> {
    let alpha_inv = alpha.inverse().unwrap();
    assert_eq!(values.len() % 2, 0);

    let half = values.len() / 2;

    let lhs = values[..half].iter().map(|&v| v * alpha);
    let rhs = values[half..].iter().map(|&v| v * alpha_inv);

    lhs.zip(rhs).map(|(lhs_v, rhs_v)| lhs_v + rhs_v).collect()
}

pub fn fold_scalars<F: Field>(alpha: F, values: &[F]) -> Vec<F> {
    fold_inner(values, alpha)
}

pub fn fold_bases_affine<G: AffineRepr>(alpha: G::ScalarField, values: &[G]) -> Vec<G> {
    let alpha_inv = alpha.inverse().unwrap();
    assert_eq!(values.len() % 2, 0);

    let half = values.len() / 2;

    let lhs = values[..half].iter().map(|&v| v * alpha_inv);
    let rhs = values[half..].iter().map(|&v| v * alpha);

    let res_proj: Vec<G::Group> = lhs.zip(rhs).map(|(lhs_v, rhs_v)| lhs_v + rhs_v).collect();
    G::Group::normalize_batch(&res_proj)
}

pub fn fold_bases<G: CurveGroup>(alpha: G::ScalarField, values: &[G]) -> Vec<G> {
    let alpha_inv = alpha.inverse().unwrap();
    fold_inner(values, alpha_inv)
}

pub fn compute_betas<F: Field>(alpha_1: F, alpha_2: F, alpha_3: F) -> (F, F, F) {
    let alpha_1_sq = alpha_1 * alpha_1;
    let alpha_2_sq = alpha_2 * alpha_2;
    let alpha_3_sq = alpha_3 * alpha_3;

    let beta_1 = {
        let nom = {
            alpha_1_sq * (alpha_2_sq + alpha_3_sq)
        };

        let denom = {
            (alpha_1_sq - alpha_2_sq) * (alpha_1_sq - alpha_3_sq)
        };

        - nom * denom.inverse().unwrap()
    };

    let beta_2 = {
        let nom = {
            alpha_2_sq * (alpha_1_sq + alpha_3_sq)
        };

        let denom = {
            (alpha_1_sq - alpha_2_sq) * (alpha_2_sq - alpha_3_sq)
        };

        nom * denom.inverse().unwrap()
    };

    let beta_3 = {
        let nom = {
            (alpha_3_sq) * (alpha_1_sq + alpha_2_sq)
        };

        let denom = {
            (alpha_1_sq - alpha_3_sq) * (alpha_3_sq - alpha_2_sq)
        };

        nom * denom.inverse().unwrap()
    };

    (beta_1, beta_2, beta_3)
}

/// Given three accepting u_{i+1}'s, extract u_i
pub fn extract<F: Field>
(
    u1: &[F], 
    u2: &[F],
    u3: &[F],
    alpha_1: F, 
    alpha_2: F, 
    alpha_3: F, 
    beta_1: F, 
    beta_2: F, 
    beta_3: F
) -> Vec<F> {
    let ui_left = |u: &[F], beta_i: &F, alpha_i: &F| {
        let alpha_i_inv = alpha_i.inverse().unwrap();
        u.iter().map(|&v| v * *beta_i * alpha_i_inv).collect::<Vec<_>>()
    };

    let ui_right = |u: &[F], beta_i: &F, alpha_i: &F| {
        u.iter().map(|&v| v * *beta_i * *alpha_i).collect::<Vec<_>>()
    };

    let u1_left = ui_left(u1, &beta_1, &alpha_1);
    let u1_right = ui_right(u1, &beta_1, &alpha_1);
    let u2_left = ui_left(u2, &beta_2, &alpha_2);
    let u2_right = ui_right(u2, &beta_2, &alpha_2);
    let u3_left = ui_left(u3, &beta_3, &alpha_3);
    let u3_right = ui_right(u3, &beta_3, &alpha_3);

    let u1 = u1_left.iter().chain(u1_right.iter());
    let u2 = u2_left.iter().chain(u2_right.iter());
    let u3 = u3_left.iter().chain(u3_right.iter());
    
    u1.zip(u2).zip(u3).map(|((&v1, &v2), &v3)| v1 + v2 + v3).collect::<Vec<_>>()
}

struct Protocol<G: AffineRepr, const MU: usize>(PhantomData<G>);

impl<G: AffineRepr, const MU: usize>
    protocol::Protocol<
        3,
        MU,
        Vec<G::ScalarField>,
        G::ScalarField,
        PartialTranscript<G>,
        Transcript<G>,
        Prover<G, MU>,
        Verifier<G>,
        Extractor<G>,
    > for Protocol<G, MU>
{
}

#[cfg(test)] 
mod pedersen_vc {
    use ark_bn254::{Fr as F, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;
    use ark_std::{UniformRand, test_rng, Zero};
    use rand::RngCore;
    use super::*;

    use crate::pedersen_vc::extract;
    use crate::protocol::Protocol as _;

    use super::{pedersen, compute_cross_terms, fold_scalars, compute_betas};

    fn prepare_bases<G: CurveGroup, R: RngCore>(n: usize, rng: &mut R) -> Vec<G> {
        (0..n).map(|_| G::rand(rng)).collect()
    }

    fn prepare_scalars<G: AffineRepr, R: RngCore>(n: usize, rng: &mut R) -> Vec<G::ScalarField> {
        (0..n).map(|_| G::ScalarField::rand(rng)).collect()
    }

    #[test]
    fn one_round_extract() {
        let n = 16; 
        let mut rng = test_rng();

        let u = prepare_scalars::<G1Affine, _>(n, &mut rng);

        let alpha_1 = F::rand(&mut rng);
        let alpha_2 = F::rand(&mut rng);
        let alpha_3 = F::rand(&mut rng);

        let u1 = fold_scalars(alpha_1, &u);
        let u2 = fold_scalars(alpha_2, &u);
        let u3 = fold_scalars(alpha_3, &u);

        // verifier has access to the ui_here 
        // we simply end protocol at n/2 instead of n = 1
        let (beta_1, beta_2, beta_3) = compute_betas(alpha_1, alpha_2, alpha_3);

        let u_extracted = extract(&u1, &u2, &u3, alpha_1, alpha_2, alpha_3, beta_1, beta_2, beta_3);
        assert_eq!(u_extracted, u);
    }

    #[test]
    fn pedersen_vc() {
        let mut rng = test_rng();
        let n = 16; 
        let instance = F::zero();

        let u = prepare_scalars::<G1Affine, _>(n, &mut rng);
        let g_proj = prepare_bases::<G1Projective, _>(n, &mut rng);
        let g = G1Projective::normalize_batch(&g_proj);

        let c: G1Projective = pedersen(&u, &g);
        let c = c.into_affine();

        let prover = Prover::<G1Affine, 4> { u, g: g.clone(), c };
        let verifier = Verifier::<G1Affine> {c, g};
        Protocol::<_, 4>::traverse(0, prover, verifier, PartialTranscript::default(), &mut rng, &instance);
    }
}