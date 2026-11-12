# Algorithm coverage

Pinned bee2 gitlink: `4341f7a5c300f8e6dc292559e671eb899d831433`. This is a capability audit, not a count of source references. **Tested** means a named independent vector and negative/boundary evidence exist for the group, or the noted entropy-source interface is inherently nondeterministic and its generator and lifecycle are independently tested; **partial** retains an explicit gap; **excluded** records a reason allowed by the scope. A tested row does not claim the release is ready.

BIGN profile dispatch uses the C bridge for the named profile and is verified against general BIGN with each profile’s fixed OID; a search for literal calls alone misses macro/bridge dispatch. `bakeDH` is the upstream alias of `bignDH`. BASH profile macros and BELT KWP/CTR aliases are listed with their implementations.

## `bake.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `bakeKDF`, `bakeSWU`, `bakeDH` | bake.KDF, SWU, DH | selftest.TestDiagnostics fixed KDF/SWU/DH vectors; TestKDFSWUDHInvalidInputs | tested |
| `bakeBMQV_keep`, `bakeBSTS_keep`, `bakeBPACE_keep` | — | Native state/scratch sizing is internal. | excluded |
| `bakeBMQVStart`, `bakeBMQVStep2`, `bakeBMQVStep3`, `bakeBMQVStep4`, `bakeBMQVStep5`, `bakeBMQVStepG`, `bakeBMQVRunB`, `bakeBMQVRunA` | bake.NewBMQV, session Step/Key/Run/Close | integration.TestProtocolIndependentCTranscripts (fixed C messages and keys for all confirmation combinations), TestProtocolTamperEveryMessage, TestBakeGoCInterop, TestBMQVAndBPACEConfirmations | tested |
| `bakeBSTSStart`, `bakeBSTSStep2`, `bakeBSTSStep3`, `bakeBSTSStep4`, `bakeBSTSStep5`, `bakeBSTSStepG`, `bakeBSTSRunB`, `bakeBSTSRunA` | bake.NewBSTS, session Step/Key/Run/Close | integration.TestProtocolIndependentCTranscripts (fixed C messages and keys), TestProtocolTamperEveryMessage, TestBakeGoCInterop, TestBSTSAndState | tested |
| `bakeBPACEStart`, `bakeBPACEStep2`, `bakeBPACEStep3`, `bakeBPACEStep4`, `bakeBPACEStep5`, `bakeBPACEStep6`, `bakeBPACEStepG`, `bakeBPACERunB`, `bakeBPACERunA` | bake.NewBPACE, session Step/Key/Run/Close | integration.TestProtocolIndependentCTranscripts (fixed C messages and keys for all confirmation combinations), TestProtocolTamperEveryMessage, TestBakeGoCInterop, TestBMQVAndBPACEConfirmations | tested |

## `bash.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `bashF_deep`, `bashHash_keep`, `bashPrg_keep`, `bash256_keep`, `bash384_keep`, `bash512_keep` | — | Native state/scratch sizing is internal. | excluded |
| `bashF` | — | Internal sponge permutation. | excluded |
| `bashHashStart`, `bashHashStepH`, `bashHashStepG`, `bashHashStepV`, `bashHash`, `bash256Start`, `bash256StepH`, `bash256StepG`, `bash256StepG2`, `bash256StepV`, `bash256StepV2`, `bash256Hash`, `bash384Start`, `bash384StepH`, `bash384StepG`, `bash384StepG2`, `bashHash384StepV`, `bash384StepV2`, `bash384Hash`, `bash512Start`, `bash512StepH`, `bash512StepG`, `bash512StepG2`, `bash512StepV`, `bash512StepV2`, `bash512Hash` | bash.Hash, NewHash, HashState | TestBashHashKAT; TestAllHashLevels, TestClosedHashMethodsPanic; verify prefixes with crypto/subtle.ConstantTimeCompare | tested |
| `bashPrgStart`, `bashPrgRestart`, `bashPrgAbsorbStart`, `bashPrgAbsorbStep`, `bashPrgAbsorb`, `bashPrgSqueezeStart`, `bashPrgSqueezeStep`, `bashPrgSqueeze`, `bashPrgEncrStart`, `bashPrgEncrStep`, `bashPrgEncr`, `bashPrgDecrStart`, `bashPrgDecrStep`, `bashPrgDecr`, `bashPrgRatchet` | bash.NewPRG, PRG command Start/Step, Restart, Ratchet, Close | TestPRGUpstreamRestartKAT, TestPRGEncryptKAT, TestPRGSpongeKAT; TestPRGParametersAndPhases, FuzzPRGFragments | tested |

## `bels.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `belsStdM`, `belsValM`, `belsGenM0`, `belsGenMi`, `belsGenMid` | bels.Standard, Validate, GenerateCommon, GenerateMember, Derive | TestStandardAndDerived, TestParameterAndDeterministicShareCVectors (M0/Mi fixed C vectors for all sizes), TestCustomParametersRejected | tested |
| `belsShare`, `belsShare2`, `belsShare3`, `belsRecover`, `belsRecover2` | bels.Split, ShareStandard, ShareDeterministic, Recover, RecoverStandard | TestShareCVectors, TestParameterAndDeterministicShareCVectors (Share3), TestUpstreamRecoveryVector, TestCustomParametersRejected | tested |

## `belt.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `beltH`, `beltKeyExpand`, `beltKeyExpand2`, `beltBlockEncr2`, `beltBlockEncr3`, `beltBlockDecr2`, `beltBlockDecr3`, `beltCompr`, `beltCompr2` | — | Internal substitution/key expansion/compression or duplicate word representation; byte block API below. | excluded |
| `beltBlockEncr`, `beltBlockDecr` | belt.NewBlock, Block | TestBlockKAT, TestValidation | tested |
| `beltWBL_keep`, `beltCompr_deep`, `beltECB_keep`, `beltCBC_keep`, `beltCFB_keep`, `beltCTR_keep`, `beltMAC_keep`, `beltDWP_keep`, `beltCHE_keep`, `beltHash_keep`, `beltBDE_keep`, `beltSDE_keep`, `beltFMT_keep`, `beltKRP_keep`, `beltHMAC_keep`, `beltKWP_keep` | — | Native state/scratch sizing is internal. | excluded |
| `beltWBLStart`, `beltWBLStepE`, `beltWBLStepD`, `beltWBLStepD2`, `beltWBLStepR` | belt.NewWBL, WBL methods | TestWBLKAT, TestWBLContinueReference, TestWBLSplitDecrypt | tested |
| `beltECBStart`, `beltECBStepE`, `beltECBStepD`, `beltECBEncr`, `beltECBDecr` | belt.NewECB, ECBEncrypt/Decrypt | TestECBKAT, TestCTSBounds | tested |
| `beltCBCStart`, `beltCBCRefresh`, `beltCBCStepE`, `beltCBCStepD`, `beltCBCEncr`, `beltCBCDecr` | belt.NewCBC, CBCEncrypt/Decrypt | TestCBCStreamingCTSAndRefresh, TestCTSBounds | tested |
| `beltCFBStart`, `beltCFBRefresh`, `beltCFBStepE`, `beltCFBStepD`, `beltCFBEncr`, `beltCFBDecr` | belt.NewCFB, CFBEncrypt/Decrypt | TestStreamKATFragments, TestRefreshMatchesNewState | tested |
| `beltCTRStart`, `beltCTRRefresh`, `beltCTRStepE`, `beltCTR`, `beltCTRStepD` | belt.NewCTR, CTR | TestStreamKATFragments, TestRefreshMatchesNewState | tested |
| `beltMACStart`, `beltMACStepA`, `beltMACStepG`, `beltMACStepG2`, `beltMACStepV`, `beltMACStepV2`, `beltMAC` | belt.NewMAC, MAC, MACN, MACVerify | TestBeltMACKAT, TestStreamingMAC, TestTruncatedVerification | tested |
| `beltDWPStart`, `beltDWPRefresh`, `beltDWPStepE`, `beltDWPStepI`, `beltDWPStepA`, `beltDWPStepG`, `beltDWPStepV`, `beltDWPStepD`, `beltDWPWrap`, `beltDWPUnwrap` | belt.DWPWrap/Unwrap, NewAuthenticatedStream | TestAEADKATAndTamper, TestAuthenticatedRefreshAndPhases | tested |
| `beltCHEStart`, `beltCHERefresh`, `beltCHEStepE`, `beltCHEStepI`, `beltCHEStepA`, `beltCHEStepG`, `beltCHEStepV`, `beltCHEStepD`, `beltCHEWrap`, `beltCHEUnwrap` | belt.CHEWrap/Unwrap, NewAuthenticatedStream | TestAEADKATAndTamper, TestAuthenticatedRefreshAndPhases | tested |
| `beltKWPWrap`, `beltKWPUnwrap`, `beltKWPStart`, `beltKWPStepE`, `beltKWPStepD`, `beltKWPStepD2` | belt.KWPWrap/Unwrap, WBL methods | TestKWPKAT, TestBeltKWPWrongKey | tested |
| `beltHashStart`, `beltHashStepH`, `beltHashStepG`, `beltHashStepG2`, `beltHashStepV`, `beltHashStepV2`, `beltHash` | belt.Hash, NewHash, HashN, HashVerify | TestBeltHashKAT, TestHashKATAndLifecycle, TestTruncatedVerification | tested |
| `beltBDEStart`, `beltBDERefresh`, `beltBDEStepE`, `beltBDEStepD`, `beltBDEEncr`, `beltBDEDecr` | belt.NewBDE, BDEEncrypt/Decrypt | TestDiskAndFMTKAT, TestRefreshMatchesNewState | tested |
| `beltSDEStart`, `beltSDEStepE`, `beltSDEStepD`, `beltSDEEncr`, `beltSDEDecr` | belt.NewSDE, SDEEncrypt/Decrypt | TestDiskAndFMTKAT, TestReusableStates | tested |
| `beltFMTStart`, `beltFMTStepE`, `beltFMTStepD`, `beltFMTEncr`, `beltFMTDecr` | belt.NewFMT, FMTEncrypt/Decrypt | TestFMTRadixKAT, TestValidation, FuzzFMT | tested |
| `beltKRPStart`, `beltKRPStepG`, `beltKRP` | belt.NewKRP, KRP | TestKRPAllLengthsKAT, TestValidation | tested |
| `beltHMACStart`, `beltHMACStepA`, `beltHMACStepG`, `beltHMACStepG2`, `beltHMACStepV`, `beltHMACStepV2`, `beltHMAC` | belt.NewHMAC, HMAC, HMACN, HMACVerify | TestBeltHMACKAT, TestStreamingMAC, TestTruncatedVerification | tested |
| `beltPBKDF2` | belt.PBKDF2 | TestBeltPBKDF2KAT, TestBeltPBKDF2InvalidIter | tested |

## `bign.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `bignParamsStd`, `bignParamsVal`, `bignParamsGen`, `bignParamsEnc`, `bignParamsDec` | bign.StandardParams, ParamsFromDER, Params.DER/Validate/Close, GenerateParams | TestParamsDERRoundTrip, TestGenerateParamsCallbacks, FuzzParamsDER; no general order calculator is supplied | tested |
| `bignOidToDER` | bign.OIDToDER | TestProfileDeterministicMatchesGeneral, TestMalformedOIDs, TestMalformedDERSigningOID | tested |
| `bignKeypairGen`, `bignKeypairVal`, `bignPubkeyVal`, `bignPubkeyCalc`, `bignDH`, `bignSign`, `bignSign2`, `bignVerify`, `bignKeyWrap`, `bignKeyUnwrap` | bign.GenerateKey, ValidateKeyPair, ValidatePublicKey, PublicKey, DH, SignDigest, SignDigestDeterministic, VerifyDigest, WrapKey, UnwrapKey | TestSeededCFixtures (fixed C keygen, sign, verify, DH and transport across all three curves), TestGeneralClosedAndInvalidArguments, TestMalformedDERSigningOID | tested |
| `bignIdExtract`, `bignIdSign`, `bignIdSign2`, `bignIdVerify` | bign.ExtractIdentity, SignIdentityDigest, SignIdentityDigestDeterministic, VerifyIdentityDigest | TestSeededCFixtures (fixed C identity extract, randomized/deterministic signatures and verification across all three curves, tampering), TestIdentitySignatures | tested |

## `bign128.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `bign128KeypairGen`, `bign128KeypairVal`, `bign128PubkeyVal`, `bign128PubkeyCalc`, `bign128DH`, `bign128Sign`, `bign128Sign2`, `bign128Verify`, `bign128KeyWrap`, `bign128KeyUnwrap` | bign.Profile128 methods | TestSeededCFixtures (fixed C keygen, Sign/Sign2, DH and transport), TestProfile128UpstreamVerificationAndUnwrap, TestProfileValidationAndEntropy | tested |

## `bign192.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `bign192KeypairGen`, `bign192KeypairVal`, `bign192PubkeyVal`, `bign192PubkeyCalc`, `bign192DH`, `bign192Sign`, `bign192Sign2`, `bign192Verify`, `bign192KeyWrap`, `bign192KeyUnwrap` | bign.Profile192 methods | TestSeededCFixtures (fixed C keygen, Sign/Sign2, DH and transport), TestProfileDeterministicMatchesGeneral, TestProfileValidationAndEntropy | tested |

## `bign256.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `bign256KeypairGen`, `bign256KeypairVal`, `bign256PubkeyVal`, `bign256PubkeyCalc`, `bign256DH`, `bign256Sign`, `bign256Sign2`, `bign256Verify`, `bign256KeyWrap`, `bign256KeyUnwrap` | bign.Profile256 methods | TestSeededCFixtures (fixed C keygen, Sign/Sign2, DH and transport), TestProfileDeterministicMatchesGeneral, TestProfileValidationAndEntropy | tested |

## `bign96.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `bign96KeypairGen`, `bign96KeypairVal`, `bign96PubkeyVal`, `bign96PubkeyCalc`, `bign96Sign`, `bign96Sign2`, `bign96Verify` | bign.Profile96 methods | TestSeededCFixtures (fixed C keygen, randomized/deterministic signatures), TestProfile96UpstreamDeterministicKAT, TestProfileValidationAndEntropy | tested |

## `botp.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `botpDT`, `botpCtrNext` | — | Internal truncation and counter helpers; OTP APIs own the algorithm/state. | excluded |
| `botpHOTP_keep`, `botpTOTP_keep`, `botpOCRA_keep` | — | Native state/scratch sizing is internal. | excluded |
| `botpHOTPStart`, `botpHOTPStepS`, `botpHOTPStepR`, `botpHOTPStepV`, `botpHOTPStepG`, `botpHOTPRand`, `botpHOTPVerify` | botp.NewHOTP, state methods, HOTPCode, VerifyHOTP | TestHOTPAndTOTP, TestOneShotOTPRejectsEmbeddedNUL and TestOneShotOTPRejectsNULAtEveryPosition; TestVerificationAndTOTPState; TestCounterBoundaryAndClose, TestDigitLengths | tested |
| `botpTOTPStart`, `botpTOTPStepR`, `botpTOTPStepV`, `botpTOTPRand`, `botpTOTPVerify` | botp.NewTOTP, state methods, TOTPCode, VerifyTOTP | TestHOTPAndTOTP, TestOneShotOTPRejectsEmbeddedNUL and TestOneShotOTPRejectsNULAtEveryPosition; TestVerificationAndTOTPState; TestCounterBoundaryAndClose, TestDigitLengths; TestNegativeTimeCVectors covers signed times and TIME_ERR on Linux amd64 | tested |
| `botpOCRAStart`, `botpOCRAStepS`, `botpOCRAStepR`, `botpOCRAStepV`, `botpOCRAStepG`, `botpOCRARand`, `botpOCRAVerify` | botp.ParseSuite, NewOCRA, state methods, OCRACode, VerifyOCRA | TestOCRA, TestOCRAOneShot, TestSuiteFields, FuzzParseSuite; TestCounterBoundaryAndClose, TestDigitLengths; TestNegativeTimeCVectors covers signed times and TIME_ERR on Linux amd64 | tested |

## `bpki.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `bpkiPrivkeyWrap`, `bpkiPrivkeyUnwrap` | bpki.WrapPrivateKey, UnwrapPrivateKey | TestAllContainerCVectors standalone C DER fixtures for supported sizes, TestContainers, TestAuthenticationFailures, FuzzContainers | tested |
| `bpkiShareWrap`, `bpkiShareUnwrap` | bpki.WrapShare, UnwrapShare | TestAllContainerCVectors standalone C DER fixtures for supported sizes, TestContainers, TestAuthenticationFailures, FuzzContainers | tested |
| `bpkiCSRRewrap`, `bpkiCSRUnwrap` | bpki.RewrapCSR, UnwrapCSR | TestCSR upstream fixture and altered CSR, FuzzCSR | tested |

## `brng.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `brngCTR_keep`, `brngHMAC_keep` | — | Native state/scratch sizing is internal. | excluded |
| `brngCTRStart`, `brngCTRStepR`, `brngCTRStepG`, `brngCTRRand` | brng.NewCTR, CTR.Read/Transform/IV/Close, CTRRand/CTRTransform | TestUpstreamCTRTransformAndIV upstream B.2, TestCTRReadZerosAndChunking, TestInvalidIV, TestRandBoundaries | tested |
| `brngHMACStart`, `brngHMACStepR`, `brngHMACRand` | brng.NewHMAC, HMAC.Read/Close, HMACRand | TestUpstreamHMAC upstream B.4, TestHMACOwnsLongIV, TestRandBoundaries | tested |

## `btok.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `btokPwdTransition` | btok.PasswordState.Transition | TestPasswordTransitions, TestPasswordTransitionTable | tested |
| `btokCVCCheck`, `btokCVCCheck2`, `btokCVCWrap`, `btokCVCUnwrap`, `btokCVCIss`, `btokCVCLen`, `btokCVCVal`, `btokCVCVal2`, `btokCVCMatch` | btok.CheckCertificate/CheckCertificateForIssuer, WrapCertificate, UnwrapCertificate, IssueCertificate, CertificateLength, ValidateCertificate/ForIssuer, MatchCertificate | TestCertificateCVector, TestCertificateChain, TestCertificateKeySizesAndFailures, FuzzCertificate | tested |
| `btokSM_keep`, `btokBAuthT_keep`, `btokBAuthCT_keep` | — | Native state/scratch sizing is internal. | excluded |
| `btokSMStart`, `btokSMCtrInc`, `btokSMCmdWrap`, `btokSMCmdUnwrap`, `btokSMRespWrap`, `btokSMRespUnwrap` | btok.NewSecureMessaging, Wrap/UnwrapCommand, Wrap/UnwrapResponse, Close | TestSecureMessagingVector, TestSecureMessagingRejectsTampering, TestSecureMessagingMaximumLengths, FuzzSecureMessaging | tested |
| `btokBAuthTStart`, `btokBAuthCTStart`, `btokBAuthCTStep2`, `btokBAuthTStep3`, `btokBAuthCTStep4`, `btokBAuthTStep5`, `btokBAuthCTStepG`, `btokBAuthTStepG` | btok.NewBAuthTerminal/NewBAuthToken, Step/Key/Close | integration.TestProtocolIndependentCTranscripts (fixed C messages and keys, all three levels and mutual settings), TestProtocolTamperEveryMessage, TestBAuthAllLevels, TestBAuthBadMessage; tracked backend patch applied | tested |

## `dstu.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `dstuParamsStd`, `dstuParamsVal` | dstu.Standard, Params.Validate, Params.Data, FromData | TestPinnedCFixtures (complete standard parameter fields for ten curves), TestParameterData | tested |
| `dstuPointGen`, `dstuPointVal`, `dstuPointCompress`, `dstuPointRecover` | dstu.Params.GeneratePoint, ValidatePoint, Compress, Recover, SetBasePoint | TestPinnedCFixtures (seeded generation, compression and recovery for ten curves), TestPointAndSignature | tested |
| `dstuKeypairGen`, `dstuSign`, `dstuVerify` | dstu.Params.GenerateKey, Sign, Verify | TestPinnedCFixtures (seeded keypairs/signatures for ten curves), TestUpstreamSignature, TestEmptyDigest | tested |

## `g12s.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `g12sParamsStd`, `g12sParamsVal` | g12s.Standard, Params.Validate, Params.Data, FromData | TestPinnedCFixtures (all fields for eight standard sets), TestStandardSets, TestParameterData | tested |
| `g12sKeypairGen`, `g12sSign`, `g12sVerify` | g12s.Params.GenerateKey, Sign, Verify | TestPinnedCFixtures (seeded keypairs/signatures for eight sets), TestStandardSignature, TestUpstream512 | tested |

## `pfok.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `pfokSeedVal`, `pfokSeedAdj`, `pfokParamsStd`, `pfokParamsGen`, `pfokParamsVal` | pfok.Seed.Validate/Adjust, Standard, Generate, GenerateWithProgress, Params.Validate | TestStandardParameters, TestGenerateUpstream (slow), TestGenerateProgress, TestProgressPanic (upstream fixed seed) | tested |
| `pfokKeypairGen`, `pfokPubkeyVal`, `pfokPubkeyCalc`, `pfokDH`, `pfokMTI` | pfok.Params.GenerateKey, PublicKey, ValidatePublicKey, DH, MTI | TestUpstreamAgreement, TestAgreement | tested |

## `stb99.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `stb99SeedVal`, `stb99SeedAdj`, `stb99ParamsStd`, `stb99ParamsGen`, `stb99ParamsVal` | stb99.Seed.Validate/Adjust, Standard, Generate, Params.Validate | TestStandardAndSeed, TestGenerateUpstream (slow), TestInvalidInputs; no sign/verify in pinned header | tested |

## `rng.h`

| Upstream symbols | Public Go API | Evidence / limitation | Status |
|---|---|---|---|
| `rngTestFIPS1`, `rngTestFIPS2`, `rngTestFIPS3`, `rngTestFIPS4`, `rngESRead`, `rngESTest`, `rngESHealth`, `rngESHealth2` | rng.ReadEntropy, TestSource, Health/Health2, TestFIPS1/2/3/4 | TestFIPSPositiveSampleAndHealth (fixed positive FIPS sample, environmental health checks), TestFIPSDiagnostics, TestEntropy | tested |
| `rngCreate`, `rngIsValid`, `rngStepR`, `rngStepR2`, `rngRekey`, `rngClose` | rng.New/NewWithSource, IsCreated, Generator.Read/ReadWithoutReseed/Rekey/Close | TestOwners, TestAdditionalEntropySource; NewWithSource reads 32 bytes by Go contract. Singleton output mixes live entropy and is nondeterministic; underlying BRNG has fixed-vector tests | tested |

## Release evidence still required

The tracked BAuth backend patch is covered by fixed C protocol transcripts for all levels and mutual settings; final-tree verification remains pending. All mapped capabilities have the cited test evidence; these fixtures compare wrappers with the pinned C backend and are not independent cryptographic implementations. Final Go/C checks, native sanitizers, longer fuzz and slow runs, and final integrated security review remain release gates. Status may change during parallel implementation; rerun the named tests against the final tree.
