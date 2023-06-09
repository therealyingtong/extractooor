use std::fmt::Debug;

use rand::RngCore;

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

pub trait Verifier: Clone {
    type Instance;
    type VerifierMessage: VerifierMessage;
    type Transcript: Transcript<VerifierMessage = Self::VerifierMessage>;
    type PartialTranscript: PartialTranscript<VerifierMessage = Self::VerifierMessage>;
    fn verify(&self, instance: &Self::Instance, tr: &Self::Transcript) -> bool;
    fn next_round<R: RngCore>(
        &mut self,
        tr: &Self::PartialTranscript,
        rng: &mut R,
    );
}

pub trait Extractor {
    type Witness;
    type PartialTranscript: PartialTranscript;
    fn extract(tr: &Vec<Self::PartialTranscript>, prev_extraction_witnesses: &Vec<Self::Witness>) -> Self::Witness;
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
    V: Verifier<Transcript = Tr, PartialTranscript = PTr, Instance = Instance>,
    E: Extractor<Witness = Witness, PartialTranscript = PTr>,
> where
    <Tr as TryFrom<PTr>>::Error: std::fmt::Debug,
{
    fn traverse<R: RngCore>(
        depth: usize,
        p: P,
        v: V,
        tr: PTr,
        rng: &mut R,
        instance: &Instance,
    ) -> Option<Witness> {
        println!("WE ARE IN RECURSIVE STEP WITH VECTOR OF LEN: {:?}", p.witness());
        let mut p = p.clone();
        let mut v = v.clone();
        v.next_round(&tr, rng);
        println!("SURVIVED V");
        let prover_message = p.next_round(&tr, rng);
        println!("SURVIVED P");

        let tr = tr.append_prover_message(prover_message);

        if depth == MU {
            println!("WE ARE IN THE LEAF!!!!");
            let verification_result: bool = v.verify(instance, &tr.clone().try_into().unwrap());

            if verification_result {
                return Some(p.witness());
            } else {
                return None;
            }
        }

        let mut accepting_transcripts = Vec::<PTr>::with_capacity(WIDTH);
        let mut accepting_witnesses = Vec::<Witness>::with_capacity(WIDTH);


        while accepting_transcripts.len() < WIDTH {
            let c: PTr::VerifierMessage = VerifierMessage::rand(rng);
            let tr_result = Self::traverse(
                depth + 1,
                p.clone(),
                v.clone(),
                tr.append_verifier_message(c.clone()),
                rng,
                instance,
            );

            // leftmost child
            if accepting_transcripts.len() == 0 {
                if let Some(u) = tr_result {
                    accepting_transcripts.push(tr.append_verifier_message(c.clone()));
                    accepting_witnesses.push(u);
                } else {
                    return None;
                }
            // any other child
            } else {
                if let Some(u) = tr_result {
                    accepting_transcripts.push(tr.append_verifier_message(c.clone()));
                    accepting_witnesses.push(u);
                }
            }
        }

        let extracted_witness: Witness = E::extract(
            &accepting_transcripts,
            &accepting_witnesses
        );

        // given array of accepting transcripts
        // extraction always succeeds
        if extracted_witness != p.witness() {
            println!("extracted_witness: {:?}", extracted_witness);
            println!("p.witness(): {:?}", p.witness());
            panic!("Protocol does not accept from array of accepting transcripts");
        }

        Some(extracted_witness)
    }
}
