use std::marker::PhantomData;

use rand::RngCore;

use crate::protocol::{PartialTranscript, Prover, Transcript, Verifier, Extractor, Protocol};

struct TraversalResult<T: Transcript>(T);

struct Node<
    const WIDTH: usize,
    const MU: usize,
    Witness,
    Instance,
    PTr: PartialTranscript,
    Tr: Transcript + TryFrom<PTr>,
    P: Prover<Witness = Witness, PartialTranscript = PTr>,
    V: Verifier<Transcript = Tr, Instance = Instance>,
    E: Extractor<Witness = Witness, Transcript = Tr>,
    Pr: Protocol<
        MU, Witness, Instance, PTr, Tr, P, V, E
    >
>(PhantomData<(P, V, E, Pr, PTr)>);

impl<
    const WIDTH: usize,
    const MU: usize,
    Witness,
    Instance,
    PTr: PartialTranscript,
    Tr: Transcript + TryFrom<PTr>,
    P: Prover<Witness = Witness, PartialTranscript = PTr>,
    V: Verifier<Transcript = Tr, Instance = Instance>,
    E: Extractor<Witness = Witness, Transcript = Tr>,
    Pr: Protocol<
        MU, Witness, Instance, PTr, Tr, P, V, E
    >
> Node<WIDTH, MU, Witness, Instance, PTr, Tr, P, V, E, Pr>
{
    pub fn traverse<R: RngCore>(depth: usize, p: P, tr: PTr, rng: &mut R, instance: &Instance) -> Option<Tr> {
        let mut p = p.clone();
        let p = p.next_round(&tr);

        if depth == MU { 
            let verification_result = V::verify(instance, tr);

            if verification_result {
                return None
            } else {
                return Some(tr)
            }
        }

        let mut accepting_transcripts = Vec::<PTr>::with_capacity(WIDTH);

        for i in 0..WIDTH {
            let mut tr_result = Self::traverse(depth + 1, p, tr.append_verifer_message(Pr::VerifierMessage::rand(&mut rng)), rng, instance);

            match i {
                0 => {
                    if let tr_result = Some(tr_result) {
                        accepting_transcripts.push(tr_result)
                    } else {
                        return None;
                    }
                }
                _ => {
                    while tr_result == None {
                        tr_result = Self::traverse(depth + 1, p, tr.append_verifer_message(Pr::VerifierMessage::rand(&mut rng)), rng, instance);
                    }
                }
            }
        }
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
        todo!()
    }
}
