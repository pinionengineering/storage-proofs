# Storage Proofs

Thie repository contains an implementation for several remote proof of storage schemes.
Each fo the protocols in this repository share a common concern, which is to prove, through a challenge-responce protocol, that a remote party is storing a file.

If there is a protocol you believe should be implemented here, or if you have a suggestion, please open an issue or a pull request.

## Protocols

Protocols are broken down into two broad categories: Proofs of Data Possession (PDP) and Proofs of Retrievability (POR).
PDP protocols that produce a probability that the data is being stored.
POR protocols provide a stronger garuantee that the entire file is being stored and an extractor to retrieve the file by collecting challenge responses.

PDP: 
ateniese: Provable Data Possession, by Ateniese et al. (2007)
erway: Dynamic Provable Data Possession, by Erway et al. (2009)

POR:
sw: Scalable and Efficient Provable Data Possession, by Shacham and Waters (2008)
bjo: Proofs of Retrievability, by Juels and Kaliski (2007), Bowers, Juels, and Oprea (2009)


## Organization

### core logic
The core storage proof logic is organized in a way that each protocol has its own directory under 'pdp' and 'por'.
Each of these protocols are intended to match the original paper as closely as possible.
These are math-heavy implementations and they should have lots of comments referencing the paper.
Variable names are chosen to match the paper closely. You should ideally be able to read the paper
and the code side by side and see the connection between the two.

### suite
This directory *is* allowed to be imported into the core logic.
The papers are, at times, ambiguous about cryptographic primitives, hash functions, and other details.
The suite sets up a collection of primative algorithms that can be referenced as a group.

### blocks
This directory *is* allowed to be imported into the core logic.
In all of the papers, data is a collection of blocks that are tagged and challenged.
A simple block abstraction is implemented here.

### confidence
This directory *is not* allowed to be imported into the core logic.
It contains helper function to calculate the confidence that a file is being stored on a remote party, given the actual responses to challenges.
The protocol papers do not define such a function, and it's not always appropriate.

### line
This directory *is not* allowed to be imported into core logic.
This directory *is* what we anticpate to be the most useful import for applications.
Here, we implement interfaces for the core logic and adapters for each of the core protocols.
Whereas in the core logic implementations, we are trying to match the literature as closely as possible, we take the opposite approach here.
This is an abstract interface that hides all the details of the underlying protocols.

### cmd
This directory contains some utilities that are useful for testing and debugging the protocols. We use them to produce charts and understand the behavior of the protocols.

## Demo
We have a demo in cmd/linedemo.

Our demo server is a file server that stores a single file, and the associated tags.
Our demo client tags and uploads the file and then runs the challenge response protocol with the server every 10 seconds.
