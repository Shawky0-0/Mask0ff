---
tags: [security, flash, advisories, method, api, batch, access-control]
updated: 2026-08-12
sources:
  - "https://hadrian.io/blog/wp2shell-a-pre-authentication-rce-in-wordpress-cores-rest-batch-api accessed 2026-08-12"
  - "https://blog.securelayer7.net/cve-2026-63030-cve-2026-60137-wp2shell-pre-auth-rce-in-wordpress-core-via-rest-batch-route-confusion-and-sql-injection/ accessed 2026-08-12"
  - "security/advisories-api/entries/APIDS-0002.md"
---

# MTH-API-002: break one item in a batch and watch the others answer for each other

**The technique in one line.** Where an endpoint processes a list in two passes, put a
deliberately invalid item early in the list and check whether the later items are still handled
by the right handler, because a skipped entry on one side of a positional join shifts every
decision after it.

Related: MTH-API-001, the object graph,
APIDS-0002, where this was found,
the API folder.

## The discovery signal

The signal is **a batch endpoint that reports per item results**. That is it, and it is
usually visible from the documentation alone.

A batch endpoint has to do two things: work out what each item is, and then do it. Almost every
implementation makes that two passes over the same list, because you want to validate the whole
batch before executing any of it. Two passes over one list need a way to find each other, and
the cheapest way is position.

Position is a fragile join key, because it holds only if both passes agree on how many entries
exist. Any path that skips an append on one side breaks it. Error paths are where appends get
skipped, because that is the branch nobody writes tests for.

So the question that finds this: **when an item fails early, does the bookkeeping still get an
entry for it?** In review that is a visible property. In black box testing you cause the failure
and watch what happens to the items after it.

The reason this is worth a card rather than a footnote is that **the tester supplies the
failure**. You are not waiting for a malformed request to occur, you are inserting one, and you
choose its position, which means you choose the offset.

## The mechanism

Two passes, one list, joined by index:

1. Validation walks the list and records, for each item, what it is and who may do it.
2. Execution walks the list and, for item `i`, reads the decision at position `i`.

Insert an item that fails in pass one and gets recorded in only one of the two structures. From
that point the lists have different lengths. Item 2 in the execution pass now reads the decision
that belongs to item 3.

The consequence is not a skipped check. The check ran, and it passed, about a different item.
The permission decision for a permitted operation gets applied to a different operation. That is
a confused deputy, and it is why the result can be so much worse than the individual items
suggest: an anonymous caller pairs a request they are not allowed to make with a decision made
about one they are.

## Which class this belongs to

`API5:2023` broken function level authorisation, primarily, since what lands is a function the
caller had no right to. `API1:2023` follows when the mis dispatched handler operates on objects.

It is worth saying plainly that **this class is invisible to the object graph method**
(MTH-API-001) and to authorisation matrices in
general. Those test one request at a time against one object. Here every individual request is
correctly handled; the defect only exists in the relationship between items in one batch. A
matrix with every cell correct will still miss it. That is the argument for keeping both methods
rather than treating the matrix as complete coverage.

## Which protocols it applies to

* **REST batch and bulk endpoints.** The original case.
* **GraphQL**, in two forms: batched queries sent as an array, and aliased fields inside one
  query. Both are lists processed in passes, and both have historically had validation and
  execution walk them separately.
* **JSON:API bulk operations**, and any custom import, bulk update or multi delete route.
* **Webhook fan out and queue consumers** that validate a batch of messages then process them,
  which is the same shape moved off the HTTP path.

## A safe way to test for it

The safe proof is an **error origin mismatch**, and it writes nothing.

1. Find two routes whose permission failures return **different and recognisable** error codes.
   Call each one alone first and write the codes down. This step is not optional; without it
   there is nothing to compare against.
2. Send a batch of three: item one deliberately malformed so it fails parsing, items two and
   three addressing those two routes.
3. Read the errors. If item two comes back carrying item three's error, the join is broken.

Nothing is created and nothing is written, so no canary is needed. The observable is a string.

**Stop at the mismatch.** Where this was found, the next step in the published chain was SQL
injection and then code execution. The mismatch is the finding; the chain adds nothing to it
except risk.

## The control that catches a false positive

The one that matters: **response ordering is not the same thing as handler binding.** Some batch
implementations legitimately return results in completion order rather than request order, so
"the errors came back in a surprising order" proves nothing on its own. The claim requires the
error to be one that only that other route produces. That is why step one exists.

Two more:

* **The well formed control.** Send the same batch with item one valid. The errors must now
  line up with the routes addressed. If they are jumbled either way, the endpoint never promised
  positional correspondence and there is no finding.
* **Distinguish a generic refusal.** A uniform 403 across every item is an endpoint that refused
  the whole batch, which is normal behaviour, not desynchronisation.

## Where else this shape appears

Widen the pattern past batches: **any two collections that must stay index aligned while
something iterates them, where one has a path that skips an append.** Parallel arrays are the
obvious form. The same defect appears as:

* a results array and an errors array maintained side by side;
* a list of parsed items and a separate list of their permissions, capabilities or owners;
* zipped iteration over two sequences where one was filtered and the other was not, which is a
  very common shape in Python and JavaScript pipeline code;
* offset or cursor bookkeeping where a skipped record does not advance a counter.

**The general review question, which is the thing to keep:** when two lists must line up, what
happens on the error path, and is position doing work that an explicit identifier should be
doing instead.

## Recall question

Why does an authorisation matrix with every cell correct still miss this bug, and what does the
