package crypto

import "filippo.io/edwards25519"

// Point represents a point on the edwards25519 curve.
//
// The zero value is not valid, and it may be used only as a receiver.
type Point = edwards25519.Point

// A Scalar is an integer modulo
//
//     l = 2^252 + 27742317777372353535851937790883648493
//
// which is the prime order of the edwards25519 group.
//
// The zero value is a valid zero element.
type Scalar = edwards25519.Scalar

// NewScalar returns a new zero Scalar.
var NewScalar = edwards25519.NewScalar

// NewGeneratorPoint returns a new Point set to the canonical generator.
var NewGeneratorPoint = edwards25519.NewGeneratorPoint

// NewIdentityPoint returns a new Point set to the identity.
var NewIdentityPoint = edwards25519.NewIdentityPoint
