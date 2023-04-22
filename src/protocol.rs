use rand::RngCore;

pub trait ProverMessage: Clone {}
pub trait VerifierMessage: Clone {
    fn rand<R: RngCore>(rng: &mut R) -> Self;
}

pub trait Prover: Clone {
    type Witness: Clone;
    type ProverMessage: ProverMessage;
    type PartialTranscript: PartialTranscript;
    fn witness(&self) -> Self::Witness;
    fn next_round(&mut self, tr: &Self::PartialTranscript) -> Self::ProverMessage;
}

pub trait Verifier {
    type Instance;
    type VerifierMessage: VerifierMessage;
    type Transcript: Transcript<VerifierMessage = Self::VerifierMessage>;
    fn verify(instance: Self::Instance, tr: Self::Transcript) -> bool;
}

pub trait Extractor {
    type Witness;
    type Transcript: Transcript;
    fn extract(tr: Vec<Self::Transcript>) -> Self::Witness;
}

pub trait PartialTranscript: Clone {
    type ProverMessage: ProverMessage;
    type VerifierMessage: VerifierMessage;

    fn round_index(&self) -> usize;
    fn verifier_messages(&self) -> Vec<Self::VerifierMessage>;
    fn prover_messages(&self) -> Vec<Self::ProverMessage>;
    fn append_verifer_message(&self, verifier_message: Self::VerifierMessage) -> Self;
}

pub trait Transcript {
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
    Tr: Transcript + TryFrom<PTr>,
    P: Prover<Witness = Witness, PartialTranscript = PTr>,
    V: Verifier<Transcript = Tr, Instance = Instance>,
    E: Extractor<Witness = Witness, Transcript = Tr>,
>
{
    fn invoke_extractor(transcripts: Vec<Tr>) -> E;
}
