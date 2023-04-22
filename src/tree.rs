use std::marker::PhantomData;

use rand::{RngCore, SeedableRng};

use crate::protocol::{
    Extractor, PartialTranscript, Protocol, Prover, Transcript, Verifier, VerifierMessage,
};

#[derive(Debug, PartialEq, Clone)]
pub enum TraversalResult {
    Abort,
    Success,
}

struct Node<
    const WIDTH: usize,
    const MU: usize,
    Witness,
    Instance,
    PTr: PartialTranscript,
    Tr: Transcript<ProverMessage = PTr::ProverMessage> + TryFrom<PTr>,
    P: Prover<Witness = Witness, PartialTranscript = PTr, ProverMessage = Tr::ProverMessage>,
    V: Verifier<Transcript = Tr, Instance = Instance>,
    E: Extractor<Witness = Witness, Transcript = Tr>,
    Pr: Protocol<MU, Witness, Instance, PTr, Tr, P, V, E>,
>(PhantomData<(P, V, E, Pr, PTr)>);

impl<
        const WIDTH: usize,
        const MU: usize,
        Witness,
        Instance,
        PTr: PartialTranscript,
        Tr: Transcript<ProverMessage = PTr::ProverMessage> + TryFrom<PTr>,
        P: Prover<Witness = Witness, PartialTranscript = PTr, ProverMessage = Tr::ProverMessage>,
        V: Verifier<Transcript = Tr, Instance = Instance>,
        E: Extractor<Witness = Witness, Transcript = Tr>,
        Pr: Protocol<MU, Witness, Instance, PTr, Tr, P, V, E>,
    > Node<WIDTH, MU, Witness, Instance, PTr, Tr, P, V, E, Pr>
where
    <Tr as TryFrom<PTr>>::Error: std::fmt::Debug,
{
    pub fn traverse<R: RngCore + SeedableRng>(
        depth: usize,
        p: P,
        tr: PTr,
        rng: &mut R,
        instance: &Instance,
    ) -> TraversalResult {
        let mut p = p.clone();
        let prover_message = p.next_round(&tr, rng);

        if depth == MU {
            let verification_result: bool = V::verify(instance, &tr.try_into().unwrap());

            if verification_result {
                return TraversalResult::Abort;
            } else {
                return TraversalResult::Success;
            }
        }

        let tr = tr.append_prover_message(prover_message);
        let mut accepting_transcripts = Vec::<PTr>::with_capacity(WIDTH);

        while accepting_transcripts.len() < WIDTH {
            let c: PTr::VerifierMessage = VerifierMessage::rand(rng);
            let tr_result: TraversalResult = Self::traverse(
                depth + 1,
                p.clone(),
                tr.append_verifier_message(c.clone()),
                rng,
                instance,
            );

            // leftmost child
            if accepting_transcripts.len() == 0 {
                if tr_result == TraversalResult::Success {
                    accepting_transcripts.push(tr.append_verifier_message(c.clone()));
                } else {
                    return TraversalResult::Abort;
                }
            // any other child
            } else {
                if tr_result == TraversalResult::Success {
                    accepting_transcripts.push(tr.append_verifier_message(c.clone()));
                }
            }
        }

        TraversalResult::Success
        /*
           // for i = 0; i < widht; i++ {
               tr <- call traverse with (prover.clone, append new random thing)
               if i = 0 and tr == abort {
                   abort
               }
               if i > 0 and tr == abort {
                   tr <- call leaf with different randomness again
               }
               else {
                   push tr to array of accepting
               }
           }

           given array of accepting
               - invoke extractor
               - extract the witness
        */
        // todo!()
    }
}
