use std::marker::PhantomData;

use crate::protocol;
use crate::protocol::{PartialTranscript as _, Transcript as _};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, Field};
use ark_std::{rand::RngCore, UniformRand};
use rand::SeedableRng;

/*
Schnorr

            U
         /     \
     c_1        c_2
     /           \
    /             \
   z_1            z_2
*/

const SCHNORR_MU: usize = 1;

#[derive(Clone, Debug)]
pub enum ProverMessage<G: AffineRepr> {
    /// U = [r]G
    U(G),
    /// z = r + cx
    Z(G::ScalarField),
}

impl<G: AffineRepr> ProverMessage<G> {
    fn u(&self) -> G {
        match self {
            Self::U(u) => *u,
            _ => panic!(),
        }
    }

    fn z(&self) -> G::ScalarField {
        match self {
            Self::Z(z) => *z,
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
struct Prover<G: AffineRepr> {
    x: G::ScalarField,
    r: Option<G::ScalarField>,
}

impl<G: AffineRepr> Prover<G> {
    fn first_round<R: RngCore>(&mut self, rng: &mut R) -> ProverMessage<G> {
        let r = G::ScalarField::rand(rng);
        self.r = Some(r);
        let g = G::generator();

        ProverMessage::U(g.mul(r).into_affine())
    }

    fn second_round(&mut self, tr: &PartialTranscript<G>) -> ProverMessage<G> {
        let r = self.r.unwrap();
        let c = tr.verifier_messages()[0].0;

        ProverMessage::Z(c + self.x * r)
    }
}

impl<G: AffineRepr> protocol::Prover for Prover<G> {
    type Witness = G::ScalarField;
    type ProverMessage = ProverMessage<G>;
    type PartialTranscript = PartialTranscript<G>;
    fn witness(&self) -> Self::Witness {
        self.x
    }

    fn next_round<R: RngCore>(
        &mut self,
        tr: &PartialTranscript<G>,
        rng: &mut R,
    ) -> Self::ProverMessage {
        if tr.round_index() == 0 {
            self.first_round(rng)
        } else if tr.round_index() == 1 {
            self.second_round(&tr)
        } else {
            panic!("Round index cannot exceed 1")
        }
    }
}

struct Verifier<G: AffineRepr> {
    // H = [x]G
    h: G,
}

impl<G: AffineRepr> protocol::Verifier for Verifier<G> {
    type VerifierMessage = VerifierMessage<G::ScalarField>;
    type Instance = G;
    type Transcript = Transcript<G>;

    fn verify(instance: &Self::Instance, tr: &Self::Transcript) -> bool {
        let g = G::generator();
        let u = tr.prover_messages()[0].u();
        let z = tr.prover_messages()[1].z();
        let c = tr.verifier_messages()[0].0;

        // [z]G ?= U + [c]H
        g.mul(z) == u.into() + instance.mul(c)
    }
}

struct Extractor<G: AffineRepr> {
    _marker: PhantomData<G>,
}

impl<G: AffineRepr> protocol::Extractor for Extractor<G> {
    type Witness = G::ScalarField;
    type PartialTranscript = PartialTranscript<G>;

    fn extract(trs: &Vec<Self::PartialTranscript>) -> Self::Witness {
        assert_eq!(trs.len(), 2);
        let c1 = trs[0].verifier_messages()[0].0;
        println!("c1: {}", c1);
        let c2 = trs[1].verifier_messages()[0].0;
        println!("c2: {}", c2);

        let z1 = trs[0].prover_messages()[1].z();
        println!("z1: {}", z1);
        let z2 = trs[1].prover_messages()[1].z();
        println!("z2: {}", z2);

        println!("z1 - z2: {}", z1 - z2);
        println!(
            "(c1 - c2).inverse().unwrap(): {}",
            (c1 - c2).inverse().unwrap()
        );

        let extracted_x = (z1 - z2) * (c1 - c2).inverse().unwrap();
        println!("extracted_x: {}", extracted_x);

        extracted_x
    }
}

struct Protocol<G: AffineRepr>(PhantomData<G>);

impl<G: AffineRepr>
    protocol::Protocol<
        2,
        SCHNORR_MU,
        G::ScalarField,
        G,
        PartialTranscript<G>,
        Transcript<G>,
        Prover<G>,
        Verifier<G>,
        Extractor<G>,
    > for Protocol<G>
{
}

#[cfg(test)]
mod schnorr_extractor {
    use std::ops::Mul;

    use ark_bn254::{Fr as F, G1Affine};
    use ark_ec::AffineRepr;
    use ark_ff::Field;
    use ark_std::{test_rng, UniformRand};
    // use crate::tree::Tree;

    use crate::protocol::Protocol as _;

    use super::*;

    #[test]
    fn extract() {
        let mut rng = test_rng();
        let g = G1Affine::generator();
        let x = F::rand(&mut rng);

        // Round 1:
        // - sample random r
        // - compute u = [r]G
        let r = F::rand(&mut rng);

        // First execution
        // Round 2:
        // - verifier challenge c_1
        let c_1 = F::rand(&mut rng);

        // Round 3:
        // - z_1 = r + x * c_1
        let z_1 = r + x * c_1;

        // Rewind

        // Second execution
        // Round 2:
        // - verifier challenge c_2
        let c_2 = F::rand(&mut rng);
        assert_ne!(c_1, c_2);

        // Round 3:
        // - z_2 = r + x * c_2
        let z_2 = r + x * c_2;

        // x = (z_1 - z_2) / (c_1 - c_2)
        let extracted_x = (z_1 - z_2) * (c_1 - c_2).inverse().unwrap();
        assert_eq!(x, extracted_x);
    }

    #[test]
    fn schnorr() {
        let mut rng = test_rng();
        let x = F::from(100u64);
        let instance = G1Affine::generator().mul(x).into_affine();
        let prover = Prover::<G1Affine> { x, r: None };
        Protocol::traverse(0, prover, PartialTranscript::default(), &mut rng, &instance);
    }
}
