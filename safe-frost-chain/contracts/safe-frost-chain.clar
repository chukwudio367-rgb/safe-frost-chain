;; SafeFrostChain - Zero-Knowledge Identity Verification System
;; A simplified implementation for Stacks blockchain

;; Error codes
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_CREDENTIAL (err u101))
(define-constant ERR_INSUFFICIENT_ATTESTORS (err u102))
(define-constant ERR_ALREADY_EXISTS (err u103))
(define-constant ERR_NOT_FOUND (err u104))
(define-constant ERR_INSUFFICIENT_STAKE (err u105))

;; Contract constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant MIN_ATTESTORS u3)
(define-constant MIN_STAKE_AMOUNT u1000000) ;; 1 STX in micro-STX
(define-constant VERIFICATION_FEE u100000) ;; 0.1 STX

;; Data structures

;; Credential schema definition
(define-map credential-schemas
    { schema-id: uint }
    {
        name: (string-ascii 64),
        description: (string-ascii 256),
        required-attestors: uint,
        active: bool
    }
)

;; User credentials with zero-knowledge proof hash
(define-map user-credentials
    { user: principal, schema-id: uint }
    {
        proof-hash: (buff 32),
        attestation-count: uint,
        verified: bool,
        expiry-block: uint
    }
)

;; Attestor registry
(define-map attestors
    { attestor: principal }
    {
        stake-amount: uint,
        reputation-score: uint,
        active: bool,
        total-attestations: uint
    }
)

;; Attestation records
(define-map attestations
    { user: principal, schema-id: uint, attestor: principal }
    {
        attestation-hash: (buff 32),
        block-height: uint,
        valid: bool
    }
)

;; User reputation scores (anonymous tracking)
(define-map user-reputation
    { reputation-id: (buff 32) }
    {
        score: uint,
        total-verifications: uint,
        last-update-block: uint
    }
)

;; Contract data variables
(define-data-var next-schema-id uint u1)
(define-data-var total-fees-collected uint u0)

;; Read-only functions

;; Get credential schema
(define-read-only (get-credential-schema (schema-id uint))
    (map-get? credential-schemas { schema-id: schema-id })
)

;; Get user credential status
(define-read-only (get-user-credential (user principal) (schema-id uint))
    (map-get? user-credentials { user: user, schema-id: schema-id })
)

;; Get attestor info
(define-read-only (get-attestor-info (attestor principal))
    (map-get? attestors { attestor: attestor })
)

;; Check if credential is verified
(define-read-only (is-credential-verified (user principal) (schema-id uint))
    (match (map-get? user-credentials { user: user, schema-id: schema-id })
        credential (and 
            (get verified credential)
            (> (get expiry-block credential) block-height)
        )
        false
    )
)

;; Get reputation score
(define-read-only (get-reputation-score (reputation-id (buff 32)))
    (map-get? user-reputation { reputation-id: reputation-id })
)

;; Administrative functions

;; Create new credential schema (only contract owner)
(define-public (create-credential-schema 
    (name (string-ascii 64))
    (description (string-ascii 256))
    (required-attestors uint)
)
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
        (asserts! (>= required-attestors MIN_ATTESTORS) ERR_INSUFFICIENT_ATTESTORS)
        
        (let ((schema-id (var-get next-schema-id)))
            (map-set credential-schemas
                { schema-id: schema-id }
                {
                    name: name,
                    description: description,
                    required-attestors: required-attestors,
                    active: true
                }
            )
            (var-set next-schema-id (+ schema-id u1))
            (ok schema-id)
        )
    )
)

;; Attestor management

;; Register as an attestor
(define-public (register-attestor)
    (let ((existing-attestor (map-get? attestors { attestor: tx-sender })))
        (asserts! (is-none existing-attestor) ERR_ALREADY_EXISTS)
        (asserts! (>= (stx-get-balance tx-sender) MIN_STAKE_AMOUNT) ERR_INSUFFICIENT_STAKE)
        
        ;; Transfer stake to contract
        (try! (stx-transfer? MIN_STAKE_AMOUNT tx-sender (as-contract tx-sender)))
        
        (map-set attestors
            { attestor: tx-sender }
            {
                stake-amount: MIN_STAKE_AMOUNT,
                reputation-score: u100, ;; Starting reputation
                active: true,
                total-attestations: u0
            }
        )
        (ok true)
    )
)

;; Identity verification functions

;; Submit credential for verification
(define-public (submit-credential 
    (schema-id uint)
    (proof-hash (buff 32))
    (expiry-blocks uint)
)
    (begin
        ;; Pay verification fee
        (try! (stx-transfer? VERIFICATION_FEE tx-sender CONTRACT_OWNER))
        (var-set total-fees-collected (+ (var-get total-fees-collected) VERIFICATION_FEE))
        
        ;; Check if schema exists and is active
        (let ((schema (unwrap! (map-get? credential-schemas { schema-id: schema-id }) ERR_NOT_FOUND)))
            (asserts! (get active schema) ERR_INVALID_CREDENTIAL)
            
            ;; Store credential
            (map-set user-credentials
                { user: tx-sender, schema-id: schema-id }
                {
                    proof-hash: proof-hash,
                    attestation-count: u0,
                    verified: false,
                    expiry-block: (+ block-height expiry-blocks)
                }
            )
            (ok true)
        )
    )
)

;; Attestor provides attestation
(define-public (provide-attestation
    (user principal)
    (schema-id uint)
    (attestation-hash (buff 32))
)
    (let (
        (attestor-info (unwrap! (map-get? attestors { attestor: tx-sender }) ERR_UNAUTHORIZED))
        (credential (unwrap! (map-get? user-credentials { user: user, schema-id: schema-id }) ERR_NOT_FOUND))
        (schema (unwrap! (map-get? credential-schemas { schema-id: schema-id }) ERR_NOT_FOUND))
    )
        ;; Verify attestor is active
        (asserts! (get active attestor-info) ERR_UNAUTHORIZED)
        
        ;; Record attestation
        (map-set attestations
            { user: user, schema-id: schema-id, attestor: tx-sender }
            {
                attestation-hash: attestation-hash,
                block-height: block-height,
                valid: true
            }
        )
        
        ;; Update credential attestation count
        (let ((new-count (+ (get attestation-count credential) u1)))
            (map-set user-credentials
                { user: user, schema-id: schema-id }
                (merge credential { 
                    attestation-count: new-count,
                    verified: (>= new-count (get required-attestors schema))
                })
            )
        )
        
        ;; Update attestor stats
        (map-set attestors
            { attestor: tx-sender }
            (merge attestor-info { 
                total-attestations: (+ (get total-attestations attestor-info) u1)
            })
        )
        
        (ok true)
    )
)

;; Reputation management

;; Update anonymous reputation score
(define-public (update-reputation
    (reputation-id (buff 32))
    (score-delta int)
)
    (let (
        (current-rep (default-to 
            { score: u0, total-verifications: u0, last-update-block: u0 }
            (map-get? user-reputation { reputation-id: reputation-id })
        ))
    )
        ;; Only verified users can update reputation (simplified check)
        ;; In production, this would use zero-knowledge proofs
        
        (map-set user-reputation
            { reputation-id: reputation-id }
            {
                score: (if (< score-delta 0)
                    (if (> (get score current-rep) (to-uint (- 0 score-delta)))
                        (- (get score current-rep) (to-uint (- 0 score-delta)))
                        u0
                    )
                    (+ (get score current-rep) (to-uint score-delta))
                ),
                total-verifications: (+ (get total-verifications current-rep) u1),
                last-update-block: block-height
            }
        )
        (ok true)
    )
)

;; Utility functions

;; Verify credential batch (for efficiency)
(define-public (verify-credential-batch
    (credentials (list 10 { user: principal, schema-id: uint }))
)
    (ok (map is-credential-verified-helper credentials))
)

(define-private (is-credential-verified-helper (cred { user: principal, schema-id: uint }))
    (is-credential-verified (get user cred) (get schema-id cred))
)

;; Emergency functions (only contract owner)

;; Pause schema - FIXED VERSION
(define-public (pause-schema (schema-id uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
        (let ((schema (unwrap! (map-get? credential-schemas { schema-id: schema-id }) ERR_NOT_FOUND)))
            (map-set credential-schemas
                { schema-id: schema-id }
                (merge schema { active: false })
            )
            (ok true)
        )
    )
)

;; Get contract stats
(define-read-only (get-contract-stats)
    {
        next-schema-id: (var-get next-schema-id),
        total-fees-collected: (var-get total-fees-collected),
        contract-balance: (stx-get-balance (as-contract tx-sender))
    }
)
