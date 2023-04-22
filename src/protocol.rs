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
    fn next_round<R: RngCore + SeedableRng>(
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
    type Transcript: Transcript;
    fn extract(tr: Vec<Self::Transcript>) -> Self::Witness;
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

/// 2µ + 1 move interactive public coin protocol
pub trait Protocol<
    const MU: usize,
    Witness,
    Instance,
    PTr: PartialTranscript,
    Tr: Transcript<ProverMessage = PTr::ProverMessage> + TryFrom<PTr>,
    P: Prover<Witness = Witness, PartialTranscript = PTr, ProverMessage = Tr::ProverMessage>,
    V: Verifier<Transcript = Tr, Instance = Instance>,
    E: Extractor<Witness = Witness, Transcript = Tr>,
>
{
    fn invoke_extractor(transcripts: Vec<Tr>) -> E;
}
