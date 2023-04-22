use std::fmt::Debug;

use rand::{RngCore, SeedableRng};

pub trait ProverMessage: Clone + Debug {}
pub trait VerifierMessage: Clone + Debug {
    fn rand<R: RngCore>(rng: &mut R) -> Self;
}

pub trait Prover: Clone {
    type Witness: Clone;
    type ProverMessage: ProverMessage;
    type PartialTranscript: PartialTranscript;
    fn witness(&self) -> Self::Witness;
    fn next_round<R: RngCore>(
        &mut self,
        tr: &Self::PartialTranscript,
        rng: &mut R,
    ) -> Self::ProverMessage;
    // fn clone(&self, seed: u64) -> Self;
}

pub trait Verifier {
    type Instance;
    type VerifierMessage: VerifierMessage;
    type Transcript: Transcript<VerifierMessage = Self::VerifierMessage>;
    fn verify(instance: &Self::Instance, tr: &Self::Transcript) -> bool;
}

pub trait Extractor {
    type Witness;
    type PartialTranscript: PartialTranscript;
    fn extract(tr: &Vec<Self::PartialTranscript>) -> Self::Witness;
}

pub trait PartialTranscript: Clone + Debug {
    type ProverMessage: ProverMessage;
    type VerifierMessage: VerifierMessage;

    fn round_index(&self) -> usize;
    fn verifier_messages(&self) -> Vec<Self::VerifierMessage>;
    fn prover_messages(&self) -> Vec<Self::ProverMessage>;
    fn append_verifier_message(&self, verifier_message: Self::VerifierMessage) -> Self;
    fn append_prover_message(&self, prover_message: Self::ProverMessage) -> Self;
}

pub trait Transcript: Debug {
    type ProverMessage: ProverMessage;
    type VerifierMessage: VerifierMessage;

    fn verifier_messages(&self) -> Vec<Self::VerifierMessage>;
    fn prover_messages(&self) -> Vec<Self::ProverMessage>;
}

#[derive(Debug, PartialEq, Clone)]
pub enum TraversalResult {
    Abort,
    Success,
}

/// 2µ + 1 move interactive public coin protocol
pub trait Protocol<
    const WIDTH: usize,
    const MU: usize,
    Witness: PartialEq + Debug,
    Instance,
    PTr: PartialTranscript,
    Tr: Transcript<ProverMessage = PTr::ProverMessage> + TryFrom<PTr>,
    P: Prover<Witness = Witness, PartialTranscript = PTr, ProverMessage = PTr::ProverMessage>,
    V: Verifier<Transcript = Tr, Instance = Instance>,
    E: Extractor<Witness = Witness, PartialTranscript = PTr>,
> where
    <Tr as TryFrom<PTr>>::Error: std::fmt::Debug,
{
    fn traverse<R: RngCore>(
        depth: usize,
        p: P,
        tr: PTr,
        rng: &mut R,
        instance: &Instance,
    ) -> Option<PTr> {
        let mut p = p.clone();
        let prover_message = p.next_round(&tr, rng);
        let tr = tr.append_prover_message(prover_message);

        if depth == MU {
            let verification_result: bool = V::verify(instance, &tr.clone().try_into().unwrap());

            if verification_result {
                return Some(tr.clone());
            } else {
                return None;
            }
        }

        let mut accepting_transcripts = Vec::<PTr>::with_capacity(WIDTH);

        while accepting_transcripts.len() < WIDTH {
            let c: PTr::VerifierMessage = VerifierMessage::rand(rng);
            let tr_result = Self::traverse(
                depth + 1,
                p.clone(),
                tr.append_verifier_message(c.clone()),
                rng,
                instance,
            );

            // leftmost child
            if accepting_transcripts.len() == 0 {
                if let Some(tr) = tr_result {
                    accepting_transcripts.push(tr.append_verifier_message(c.clone()));
                } else {
                    return None;
                }
            // any other child
            } else {
                if let Some(tr) = tr_result {
                    accepting_transcripts.push(tr.append_verifier_message(c.clone()));
                }
            }
        }

        let extracted_witness: Witness = E::extract(&accepting_transcripts);

        // given array of accepting transcripts
        // extraction always succeeds
        if extracted_witness != p.witness() {
            println!("extracted_witness: {:?}", extracted_witness);
            println!("p.witness(): {:?}", p.witness());
            panic!("Protocol does not accept from array of accepting transcripts");
        }

        Some(accepting_transcripts[0].clone())
    }
}
