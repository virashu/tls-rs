use bnum::BUintD8;
use num_bigint::{BigInt, BigUint, Sign};

type ScalarInner = BUintD8<32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field25519(ScalarInner);

impl Field25519 {
    const DELTA: ScalarInner = ScalarInner::ZERO.overflowing_sub(Self::PRIME).0;
    const PRIME: ScalarInner = ScalarInner::from_digit(2u8)
        .pow(255)
        .saturating_sub(ScalarInner::from_digit(19u8));

    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(ScalarInner::from_digits(value) % Self::PRIME)
    }

    pub fn from_scalar(mut value: [u8; 32]) -> Self {
        value[0] &= 248;
        value[31] &= 127;
        value[31] |= 64;

        Self::from_bytes(value)
    }

    pub fn from_point(value: [u8; 32]) -> Self {
        Self::from_bytes(value)
    }

    pub fn decode_scalar(value: &str) -> Self {
        todo!()
    }

    pub fn decode_point(value: &str) -> Self {
        todo!()
    }

    /// Little-endian bytes
    pub fn into_bytes(self) -> [u8; 32] {
        *self.into_inner().digits()
    }

    pub const fn raw(value: ScalarInner) -> Self {
        Self(value)
    }

    pub fn sq(self) -> Self {
        self * self
    }

    pub fn into_inner(self) -> ScalarInner {
        self.0
    }

    // Field inversion
    pub fn inv(self) -> Field25519 {
        assert!(self.0 != ScalarInner::ZERO, "Cannot invert zero");

        let x_p1 = self;
        let x_p2 = x_p1.sq();
        let x_p9 = x_p2.sq().sq() * x_p1;
        let x_p11 = x_p9 * x_p2;

        let x5 = x_p11.sq() * x_p9;

        // let x10   = (nth double   5 `andThen` add x5   ) x5
        let mut t = x5;
        for _ in 0..5 {
            t = t.sq();
        }
        let x10 = t * x5;

        // let x20   = (nth double  10 `andThen` add x10  ) x10
        let mut t = x10;
        for _ in 0..10 {
            t = t.sq();
        }
        let x20 = t * x10;

        // let x40   = (nth double  20 `andThen` add x20  ) x20
        let mut t = x20;
        for _ in 0..20 {
            t = t.sq();
        }
        let x40 = t * x20;

        // let x50   = (nth double  10 `andThen` add x10  ) x40
        let mut t = x40;
        for _ in 0..10 {
            t = t.sq();
        }
        let x50 = t * x10;

        // let x100  = (nth double  50 `andThen` add x50  ) x50
        let mut t = x50;
        for _ in 0..50 {
            t = t.sq();
        }
        let x100 = t * x50;

        // (nth double 100 `andThen` add x100   `andThen`
        //  nth double  50 `andThen` add x50    `andThen`
        //  nth double   5 `andThen` add _1011) x100
        let mut y = x100;

        for _ in 0..100 {
            y = y.sq();
        }
        y = y * x100;

        for _ in 0..50 {
            y = y.sq();
        }
        y = y * x50;

        for _ in 0..5 {
            y = y.sq();
        }
        y = y * x_p11;

        y
    }

    // Scalar inversion
    // pub fn inv_a(self) -> Scalar {
    //     let x = self;

    //     let x2 = x * x;
    //     let x3 = x * x2;
    //     let x4 = x2 * x2;
    //     let x5 = x2 * x3;
    //     let x7 = x2 * x5;
    //     let x9 = x2 * x7;
    //     let x11 = x2 * x9;
    //     let x15 = x4 * x11;
    //     let x16 = x * x15;
    //     let mut y = x16;

    //     macro_rules! sq_mul {
    //         ($sq:expr, $mul:expr) => {
    //             for _ in 0..$sq {
    //                 y = y * y;
    //             }
    //             y = y * $mul;
    //         };
    //     }

    //     sq_mul!(126, x5); // 257
    //     sq_mul!(4, x3); // 11
    //     sq_mul!(5, x15); // 25
    //     sq_mul!(5, x15); // 25

    //     sq_mul!(4, x9); // 17
    //     sq_mul!(2, x3); // 7
    //     sq_mul!(5, x15); // 25
    //     sq_mul!(4, x5); // 13

    //     sq_mul!(6, x5); // 17
    //     sq_mul!(3, x7); // 13
    //     sq_mul!(5, x15); // 25
    //     sq_mul!(5, x7); // 17

    //     sq_mul!(4, x3); // 11
    //     sq_mul!(5, x11);
    //     sq_mul!(6, x11);
    //     sq_mul!(10, x9);

    //     sq_mul!(4, x3);
    //     sq_mul!(5, x3);
    //     sq_mul!(5, x3);
    //     sq_mul!(5, x9);

    //     sq_mul!(4, x7);
    //     sq_mul!(6, x15);
    //     sq_mul!(5, x11);
    //     sq_mul!(3, x5);

    //     sq_mul!(6, x15);
    //     sq_mul!(3, x5);
    //     sq_mul!(3, x3);

    //     y
    // }
}

impl std::ops::Add for Field25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let a = self.0;
        let b = rhs.0;

        let (mut c, overflow) = a.overflowing_add(b);

        if overflow {
            c += Self::DELTA;
        }

        Self(c % Self::PRIME)
    }
}

impl std::ops::Sub for Field25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let a = BigInt::from_bytes_le(Sign::Plus, self.0.digits());
        let b = BigInt::from_bytes_le(Sign::Plus, rhs.0.digits());

        let mut c: BigInt = (a - b) % (BigInt::from(2u8).pow(255) - BigInt::from(19u8));

        if c.sign() == Sign::Minus {
            c += BigInt::from(2u8).pow(255) - BigInt::from(19u8);
        }

        let (sign, bytes) = c.to_bytes_le();
        assert_ne!(sign, Sign::Minus);

        Self(ScalarInner::from_le_slice(&bytes).unwrap())
    }
}

impl std::ops::Mul for Field25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let a = BigUint::from_bytes_le(self.0.digits());
        let b = BigUint::from_bytes_le(rhs.0.digits());

        let c: BigUint = (a * b) % (BigUint::from(2u8).pow(255) - BigUint::from(19u8));
        let c = ScalarInner::from_le_slice(&c.to_bytes_le()).unwrap();

        Self(c)
    }
}

impl From<u32> for Field25519 {
    fn from(value: u32) -> Self {
        Self(ScalarInner::from(value))
    }
}

impl From<ScalarInner> for Field25519 {
    fn from(value: ScalarInner) -> Self {
        Self::from_bytes(*(value % Self::PRIME).digits())
    }
}

impl std::fmt::Display for Field25519 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}
