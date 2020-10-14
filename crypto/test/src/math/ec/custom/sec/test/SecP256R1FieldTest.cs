﻿using System;
using System.Collections;
using System.Text;
using System.Text.RegularExpressions;
using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Math.EC.Custom.Sec.Tests
{
    [TestFixture]
    public class SecP256R1FieldTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly X9ECParameters DP = CustomNamedCurves
            .GetByOid(SecObjectIdentifiers.SecP256r1);
        private static readonly BigInteger Q = DP.Curve.Field.Characteristic;

        [Test]
        public void TestMultiply1()
        {
            int COUNT = 1000;

            for (int i = 0; i < COUNT; ++i)
            {
                ECFieldElement x = GenerateMultiplyInput_Random();
                ECFieldElement y = GenerateMultiplyInput_Random();

                BigInteger X = x.ToBigInteger(), Y = y.ToBigInteger();
                BigInteger R = X.Multiply(Y).Mod(Q);

                ECFieldElement z = x.Multiply(y);
                BigInteger Z = z.ToBigInteger();

                Assert.AreEqual(R, Z);
            }
        }

        [Test]
        public void TestMultiply2()
        {
            int COUNT = 100;
            ECFieldElement[] inputs = new ECFieldElement[COUNT];
            BigInteger[] INPUTS = new BigInteger[COUNT];

            for (int i = 0; i < inputs.Length; ++i)
            {
                inputs[i] = GenerateMultiplyInput_Random();
                INPUTS[i] = inputs[i].ToBigInteger();
            }

            for (int j = 0; j < inputs.Length; ++j)
            {
                for (int k = 0; k < inputs.Length; ++k)
                {
                    BigInteger R = INPUTS[j].Multiply(INPUTS[k]).Mod(Q);

                    ECFieldElement z = inputs[j].Multiply(inputs[k]);
                    BigInteger Z = z.ToBigInteger();

                    Assert.AreEqual(R, Z);
                }
            }
        }

        [Test]
        public void TestSquare()
        {
            int COUNT = 1000;

            for (int i = 0; i < COUNT; ++i)
            {
                ECFieldElement x = GenerateMultiplyInput_Random();

                BigInteger X = x.ToBigInteger();
                BigInteger R = X.Multiply(X).Mod(Q);

                ECFieldElement z = x.Square();
                BigInteger Z = z.ToBigInteger();

                Assert.AreEqual(R, Z);
            }
        }

        /**
         * Test multiplication with specifically selected values that triggered a bug in the modular
         * reduction in OpenSSL (last affected version 0.9.8g).
         *
         * See "Practical realisation and elimination of an ECC-related software bug attack", B. B.
         * Brumley, M. Barbarosa, D. Page, F. Vercauteren.
         */
        [Test]
        public void TestMultiply_OpenSSLBug()
        {
            int COUNT = 100;

            for (int i = 0; i < COUNT; ++i)
            {
                ECFieldElement x = GenerateMultiplyInputA_OpenSSLBug();
                ECFieldElement y = GenerateMultiplyInputB_OpenSSLBug();

                BigInteger X = x.ToBigInteger(), Y = y.ToBigInteger();
                BigInteger R = X.Multiply(Y).Mod(Q);

                ECFieldElement z = x.Multiply(y);
                BigInteger Z = z.ToBigInteger();

                Assert.AreEqual(R, Z);
            }
        }

        public object[] CollectTestVectors()
        {
            var testData = new ArrayList();

            var testVectorLines = System.IO.File.ReadAllLines(@"../../../test/data/nisttv.data");
            StringBuilder stringBuilder = new StringBuilder();

            string curve = null;
            BigInteger k = null;
            BigInteger x = null;
            BigInteger y = null;

            foreach (var line in testVectorLines)
            {
                var capture = new Regex(@"^ ?(\w+):? =? ?(\w+)", RegexOptions.Compiled);
                var data = capture.Match(line);

                if (!data.Success) continue;
                var nistKey = data.Groups[1].Value;
                var nistValue = data.Groups[2].Value;
                switch(nistKey)
                {
                    case "Curve":
                        // Change curve name from LNNN to L-NNN ie: P256 to P-256
                        curve = $"{nistValue.Substring(0, 1)}-{nistValue.Substring(1)}";
                        break;
                    case "k":
                        k = new BigInteger(nistValue, 10);
                        break;
                    case "x":
                        x = new BigInteger(nistValue, radix: 16);
                        break;
                    case "y":
                        y = new BigInteger(nistValue, radix: 16);
                        break;
                }

                if (null != curve && null != k && null != x && null != y)
                {
                    testData.Add(new object[]{curve, k, x, y});
                    k = null;
                    x = null;
                    y = null;
                }
            }

            return testData.ToArray();
        }

        [TestCaseSource(nameof(CollectTestVectors))]
        public void TestMultiply(string curve, BigInteger k, BigInteger expectedX, BigInteger expectedY)
        {
            // Arrange
            var x9EcParameters = Asn1.Nist.NistNamedCurves.GetByName(curve);

            // Act
            var ecPoint = x9EcParameters.G.Multiply(k);

            // Assert
            Assert.AreEqual(expectedX, ecPoint.XCoord.ToBigInteger(), "Unexpected X Coordinate");
            Assert.AreEqual(expectedY, ecPoint.YCoord.ToBigInteger(), "Unexpected Y Coordinate");
        }

        /**
         * Test squaring with specifically selected values that triggered a bug in the modular reduction
         * in OpenSSL (last affected version 0.9.8g).
         *
         * See "Practical realisation and elimination of an ECC-related software bug attack", B. B.
         * Brumley, M. Barbarosa, D. Page, F. Vercauteren.
         */
        [Test]
        public void TestSquare_OpenSSLBug()
        {
            int COUNT = 100;

            for (int i = 0; i < COUNT; ++i)
            {
                ECFieldElement x = GenerateSquareInput_OpenSSLBug();

                BigInteger X = x.ToBigInteger();
                BigInteger R = X.Multiply(X).Mod(Q);

                ECFieldElement z = x.Square();
                BigInteger Z = z.ToBigInteger();

                Assert.AreEqual(R, Z);
            }
        }

        private ECFieldElement FE(BigInteger x)
        {
            return DP.Curve.FromBigInteger(x);
        }

        private ECFieldElement GenerateMultiplyInput_Random()
        {
            return FE(new BigInteger(DP.Curve.FieldSize + 32, Random).Mod(Q));
        }

        private ECFieldElement GenerateMultiplyInputA_OpenSSLBug()
        {
            uint[] x = Nat256_Create();
            x[0] = (uint)Random.NextInt() >> 1;
            x[4] = 3;
            x[7] = 0xFFFFFFFF;

            return FE(Nat256_ToBigInteger(x));
        }

        private ECFieldElement GenerateMultiplyInputB_OpenSSLBug()
        {
            uint[] x = Nat256_Create();
            x[0] = (uint)Random.NextInt() >> 1;
            x[3] = 1;
            x[7] = 0xFFFFFFFF;

            return FE(Nat256_ToBigInteger(x));
        }

        private ECFieldElement GenerateSquareInput_OpenSSLBug()
        {
            uint[] x = Nat256_Create();
            x[0] = (uint)Random.NextInt() >> 1;
            x[4] = 2;
            x[7] = 0xFFFFFFFF;

            return FE(Nat256_ToBigInteger(x));
        }

        private static uint[] Nat256_Create()
        {
            return new uint[8];
        }

        private static BigInteger Nat256_ToBigInteger(uint[] x)
        {
            byte[] bs = new byte[32];
            for (int i = 0; i < 8; ++i)
            {
                uint x_i = x[i];
                if (x_i != 0)
                {
                    Pack_UInt32_To_BE(x_i, bs, (7 - i) << 2);
                }
            }
            return new BigInteger(1, bs);
        }

        private static void Pack_UInt32_To_BE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[off + 1] = (byte)(n >> 16);
            bs[off + 2] = (byte)(n >> 8);
            bs[off + 3] = (byte)(n);
        }
    }
}
