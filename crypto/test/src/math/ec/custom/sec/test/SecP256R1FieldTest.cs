using System;
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

        [Test]
        public void TestMultiply()
        {
            var allLines = System.IO.File.ReadAllLines(@"../../../test/data/nisttv.data");
            StringBuilder stringBuilder = new StringBuilder();
            X9ECParameters curve = null;
            BigInteger k = null;
            ECFieldElement x = null;
            ECFieldElement y = null;

            foreach (var line in allLines)
            {
                var capture = new Regex(@"^ ?(\w+):? =? ?(\w+)", RegexOptions.Compiled);
                var data = capture.Match(line);

                if (data.Success)
                {
                    var nistKey = data.Groups[1].Value;
                    var nistValue = data.Groups[2].Value;
                    switch(nistKey)
                    {
                        case "Curve":
                            stringBuilder.AppendFormat("\n Curve: {0}\n-------------\n", nistValue);

                            // Change curve name from LNNN to L-NNN ie: P256 to P-256
                            nistValue = $"{nistValue.Substring(0, 1)}-{nistValue.Substring(1)}";

                            curve = Asn1.Nist.NistNamedCurves.GetByName(nistValue);
                            break;
                        case "k":
                            if (curve != null)
                            {
                                k = new BigInteger(nistValue, 10);

                                var ecPoint = curve.G.Multiply(k);
                                x = ecPoint.XCoord;
                                y = ecPoint.YCoord;

                                stringBuilder.AppendFormat("{0} = {1}\n", nistKey, nistValue);
                                stringBuilder.AppendFormat("x = {0}\n", ecPoint.XCoord.ToString().ToUpper());
                                stringBuilder.AppendFormat("y = {0}\n", ecPoint.YCoord.ToString().ToUpper());
                                stringBuilder.AppendLine("");
                            }
                            break;
                        case "x":
                            // Assert.NotNull(x);
                            // Assert.Equals(x.ToBigInteger(), new BigInteger(nistValue, radix: 16));
                            break;
                        case "y":
                            // Assert.NotNull(y);
                            // Assert.Equals(y.ToBigInteger(), new BigInteger(nistValue, radix: 16));
                            break;
                    }
                }
            }

            // write results to file
            using (System.IO.StreamWriter file = new System.IO.StreamWriter(@"../../../test/data/bcnisttv.data"))
            {
                file.WriteLine(stringBuilder.ToString());
            }
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
