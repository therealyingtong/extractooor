// use std::marker::PhantomData;

// use rand::{RngCore, SeedableRng};

// use crate::protocol::{
//     Extractor, PartialTranscript, Protocol, Prover, Transcript, Verifier, VerifierMessage,
// };

// #[derive(Debug, PartialEq, Clone)]
// pub enum TraversalResult {
//     Abort,
//     Success,
// }

// pub struct Tree<
//     const WIDTH: usize,
//     const MU: usize,
//     Witness: PartialEq,
//     Instance,
//     PTr: PartialTranscript,
//     Tr: Transcript<ProverMessage = PTr::ProverMessage> + TryFrom<PTr>,
//     P: Prover<Witness = Witness, PartialTranscript = PTr, ProverMessage = Tr::ProverMessage>,
//     V: Verifier<Transcript = Tr, Instance = Instance>,
//     E: Extractor<Witness = Witness, PartialTranscript = PTr>,
//     Pr: Protocol<MU, Witness, Instance, PTr, Tr, P, V, E>,
// >(PhantomData<(P, V, E, Pr, PTr)>);

// impl<
//         const WIDTH: usize,
//         const MU: usize,
//         Witness: PartialEq,
//         Instance,
//         PTr: PartialTranscript,
//         Tr: Transcript<ProverMessage = PTr::ProverMessage> + TryFrom<PTr>,
//         P: Prover<Witness = Witness, PartialTranscript = PTr, ProverMessage = Tr::ProverMessage>,
//         V: Verifier<Transcript = Tr, Instance = Instance>,
//         E: Extractor<Witness = Witness, PartialTranscript = PTr>,
//         Pr: Protocol<MU, Witness, Instance, PTr, Tr, P, V, E>,
//     > Tree<WIDTH, MU, Witness, Instance, PTr, Tr, P, V, E, Pr>
// where
//     <Tr as TryFrom<PTr>>::Error: std::fmt::Debug,
// {
//     pub fn traverse<R: RngCore>(
//         depth: usize,
//         p: P,
//         tr: PTr,
//         rng: &mut R,
//         instance: &Instance,
//     ) -> TraversalResult {
//         let mut p = p.clone();
//         let prover_message = p.next_round(&tr, rng);

//         if depth == MU {
//             let verification_result: bool = V::verify(instance, &tr.try_into().unwrap());

//             if verification_result {
//                 return TraversalResult::Abort;
//             } else {
//                 return TraversalResult::Success;
//             }
//         }

//         let tr = tr.append_prover_message(prover_message);
//         let mut accepting_transcripts = Vec::<PTr>::with_capacity(WIDTH);

//         while accepting_transcripts.len() < WIDTH {
//             let c: PTr::VerifierMessage = VerifierMessage::rand(rng);
//             let tr_result: TraversalResult = Self::traverse(
//                 depth + 1,
//                 p.clone(),
//                 tr.append_verifier_message(c.clone()),
//                 rng,
//                 instance,
//             );

//             // leftmost child
//             if accepting_transcripts.len() == 0 {
//                 if tr_result == TraversalResult::Success {
//                     accepting_transcripts.push(tr.append_verifier_message(c.clone()));
//                 } else {
//                     return TraversalResult::Abort;
//                 }
//             // any other child
//             } else {
//                 if tr_result == TraversalResult::Success {
//                     accepting_transcripts.push(tr.append_verifier_message(c.clone()));
//                 }
//             }
//         }

//         let extracted_witness: Witness = E::extract(&accepting_transcripts);

//         /// given array of accepting transcripts
//         /// extraction always succeeds
//         if extracted_witness != p.witness() {
//             panic!("Protocol does not accept from array of accepting transcripts");
//         }

//         TraversalResult::Success
//     }

// }
