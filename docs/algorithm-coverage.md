# Algorithm coverage

Upstream: `4341f7a5c300f8e6dc292559e671eb899d831433`.

A capability is complete only with KAT, negative and boundary tests. This symbol inventory is a reconciliation checklist, not a functional percentage. Pending rows are not release ready.

| Header | Symbol | Status | Reason or capability/test |
|---|---|---|---|
| `bake.h` | `bakeKDF` | pending |  |
| `bake.h` | `bakeSWU` | pending |  |
| `bake.h` | `bakeBMQV_keep` | excluded | C storage sizing / scratch memory |
| `bake.h` | `bakeBMQVStart` | pending |  |
| `bake.h` | `bakeBMQVStep2` | pending |  |
| `bake.h` | `bakeBMQVStep3` | pending |  |
| `bake.h` | `bakeBMQVStep4` | pending |  |
| `bake.h` | `bakeBMQVStep5` | pending |  |
| `bake.h` | `bakeBMQVStepG` | pending |  |
| `bake.h` | `bakeBMQVRunB` | pending |  |
| `bake.h` | `bakeBMQVRunA` | pending |  |
| `bake.h` | `bakeBSTS_keep` | excluded | C storage sizing / scratch memory |
| `bake.h` | `bakeBSTSStart` | pending |  |
| `bake.h` | `bakeBSTSStep2` | pending |  |
| `bake.h` | `bakeBSTSStep3` | pending |  |
| `bake.h` | `bakeBSTSStep4` | pending |  |
| `bake.h` | `bakeBSTSStep5` | pending |  |
| `bake.h` | `bakeBSTSStepG` | pending |  |
| `bake.h` | `bakeBSTSRunB` | pending |  |
| `bake.h` | `bakeBSTSRunA` | pending |  |
| `bake.h` | `bakeBPACE_keep` | excluded | C storage sizing / scratch memory |
| `bake.h` | `bakeBPACEStart` | pending |  |
| `bake.h` | `bakeBPACEStep2` | pending |  |
| `bake.h` | `bakeBPACEStep3` | pending |  |
| `bake.h` | `bakeBPACEStep4` | pending |  |
| `bake.h` | `bakeBPACEStep5` | pending |  |
| `bake.h` | `bakeBPACEStep6` | pending |  |
| `bake.h` | `bakeBPACEStepG` | pending |  |
| `bake.h` | `bakeBPACERunB` | pending |  |
| `bake.h` | `bakeBPACERunA` | pending |  |
| `bash.h` | `bashF_deep` | excluded | C storage sizing / scratch memory |
| `bash.h` | `bashF` | excluded | internal primitive / representation helper |
| `bash.h` | `bashHash_keep` | excluded | C storage sizing / scratch memory |
| `bash.h` | `bashHashStart` | pending |  |
| `bash.h` | `bashHashStepH` | pending |  |
| `bash.h` | `bashHashStepG` | pending |  |
| `bash.h` | `bashHashStepV` | pending |  |
| `bash.h` | `bashHash` | pending |  |
| `bash.h` | `bashPrg_keep` | excluded | C storage sizing / scratch memory |
| `bash.h` | `bashPrgStart` | pending |  |
| `bash.h` | `bashPrgRestart` | pending |  |
| `bash.h` | `bashPrgAbsorbStart` | pending |  |
| `bash.h` | `bashPrgAbsorbStep` | pending |  |
| `bash.h` | `bashPrgAbsorb` | pending |  |
| `bash.h` | `bashPrgSqueezeStart` | pending |  |
| `bash.h` | `bashPrgSqueezeStep` | pending |  |
| `bash.h` | `bashPrgSqueeze` | pending |  |
| `bash.h` | `bashPrgEncrStart` | pending |  |
| `bash.h` | `bashPrgEncrStep` | pending |  |
| `bash.h` | `bashPrgEncr` | pending |  |
| `bash.h` | `bashPrgDecrStart` | pending |  |
| `bash.h` | `bashPrgDecrStep` | pending |  |
| `bash.h` | `bashPrgDecr` | pending |  |
| `bash.h` | `bashPrgRatchet` | pending |  |
| `bels.h` | `belsStdM` | pending |  |
| `bels.h` | `belsValM` | pending |  |
| `bels.h` | `belsGenM0` | pending |  |
| `bels.h` | `belsGenMi` | pending |  |
| `bels.h` | `belsGenMid` | pending |  |
| `bels.h` | `belsShare` | pending |  |
| `bels.h` | `belsShare2` | pending |  |
| `bels.h` | `belsShare3` | pending |  |
| `bels.h` | `belsRecover` | pending |  |
| `bels.h` | `belsRecover2` | pending |  |
| `belt.h` | `beltH` | excluded | internal primitive / representation helper |
| `belt.h` | `beltKeyExpand` | excluded | internal primitive / representation helper |
| `belt.h` | `beltKeyExpand2` | excluded | internal primitive / representation helper |
| `belt.h` | `beltBlockEncr` | pending |  |
| `belt.h` | `beltBlockEncr2` | excluded | duplicate C representation; covered by byte-oriented operation |
| `belt.h` | `beltBlockEncr3` | excluded | duplicate C representation; covered by byte-oriented operation |
| `belt.h` | `beltBlockDecr` | pending |  |
| `belt.h` | `beltBlockDecr2` | excluded | duplicate C representation; covered by byte-oriented operation |
| `belt.h` | `beltBlockDecr3` | excluded | duplicate C representation; covered by byte-oriented operation |
| `belt.h` | `beltWBL_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltWBLStart` | pending |  |
| `belt.h` | `beltWBLStepE` | pending |  |
| `belt.h` | `beltWBLStepD` | pending |  |
| `belt.h` | `beltWBLStepD2` | excluded | duplicate C representation; covered by byte-oriented operation |
| `belt.h` | `beltWBLStepR` | pending |  |
| `belt.h` | `beltCompr_deep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltCompr` | pending |  |
| `belt.h` | `beltCompr2` | pending |  |
| `belt.h` | `beltECB_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltECBStart` | pending |  |
| `belt.h` | `beltECBStepE` | pending |  |
| `belt.h` | `beltECBStepD` | pending |  |
| `belt.h` | `beltECBEncr` | pending |  |
| `belt.h` | `beltECBDecr` | pending |  |
| `belt.h` | `beltCBC_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltCBCStart` | pending |  |
| `belt.h` | `beltCBCRefresh` | pending |  |
| `belt.h` | `beltCBCStepE` | pending |  |
| `belt.h` | `beltCBCStepD` | pending |  |
| `belt.h` | `beltCBCEncr` | pending |  |
| `belt.h` | `beltCBCDecr` | pending |  |
| `belt.h` | `beltCFB_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltCFBStart` | pending |  |
| `belt.h` | `beltCFBRefresh` | pending |  |
| `belt.h` | `beltCFBStepE` | pending |  |
| `belt.h` | `beltCFBStepD` | pending |  |
| `belt.h` | `beltCFBEncr` | pending |  |
| `belt.h` | `beltCFBDecr` | pending |  |
| `belt.h` | `beltCTR_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltCTRStart` | pending |  |
| `belt.h` | `beltCTRRefresh` | pending |  |
| `belt.h` | `beltCTRStepE` | pending |  |
| `belt.h` | `beltCTR` | pending |  |
| `belt.h` | `beltMAC_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltMACStart` | pending |  |
| `belt.h` | `beltMACStepA` | pending |  |
| `belt.h` | `beltMACStepG` | pending |  |
| `belt.h` | `beltMACStepG2` | pending |  |
| `belt.h` | `beltMACStepV` | pending |  |
| `belt.h` | `beltMACStepV2` | pending |  |
| `belt.h` | `beltMAC` | pending |  |
| `belt.h` | `beltDWP_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltDWPStart` | pending |  |
| `belt.h` | `beltDWPRefresh` | pending |  |
| `belt.h` | `beltDWPStepE` | pending |  |
| `belt.h` | `beltDWPStepI` | pending |  |
| `belt.h` | `beltDWPStepA` | pending |  |
| `belt.h` | `beltDWPStepG` | pending |  |
| `belt.h` | `beltDWPStepV` | pending |  |
| `belt.h` | `beltDWPStepD` | pending |  |
| `belt.h` | `beltDWPWrap` | pending |  |
| `belt.h` | `beltDWPUnwrap` | pending |  |
| `belt.h` | `beltCHE_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltCHEStart` | pending |  |
| `belt.h` | `beltCHERefresh` | pending |  |
| `belt.h` | `beltCHEStepE` | pending |  |
| `belt.h` | `beltCHEStepI` | pending |  |
| `belt.h` | `beltCHEStepA` | pending |  |
| `belt.h` | `beltCHEStepG` | pending |  |
| `belt.h` | `beltCHEStepV` | pending |  |
| `belt.h` | `beltCHEStepD` | pending |  |
| `belt.h` | `beltCHEWrap` | pending |  |
| `belt.h` | `beltCHEUnwrap` | pending |  |
| `belt.h` | `beltKWPWrap` | pending |  |
| `belt.h` | `beltKWPUnwrap` | pending |  |
| `belt.h` | `beltHash_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltHashStart` | pending |  |
| `belt.h` | `beltHashStepH` | pending |  |
| `belt.h` | `beltHashStepG` | pending |  |
| `belt.h` | `beltHashStepG2` | pending |  |
| `belt.h` | `beltHashStepV` | pending |  |
| `belt.h` | `beltHashStepV2` | pending |  |
| `belt.h` | `beltHash` | pending |  |
| `belt.h` | `beltBDE_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltBDEStart` | pending |  |
| `belt.h` | `beltBDERefresh` | pending |  |
| `belt.h` | `beltBDEStepE` | pending |  |
| `belt.h` | `beltBDEStepD` | pending |  |
| `belt.h` | `beltBDEEncr` | pending |  |
| `belt.h` | `beltBDEDecr` | pending |  |
| `belt.h` | `beltSDE_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltSDEStart` | pending |  |
| `belt.h` | `beltSDEStepE` | pending |  |
| `belt.h` | `beltSDEStepD` | pending |  |
| `belt.h` | `beltSDEEncr` | pending |  |
| `belt.h` | `beltSDEDecr` | pending |  |
| `belt.h` | `beltFMT_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltFMTStart` | pending |  |
| `belt.h` | `beltFMTStepE` | pending |  |
| `belt.h` | `beltFMTStepD` | pending |  |
| `belt.h` | `beltFMTEncr` | pending |  |
| `belt.h` | `beltFMTDecr` | pending |  |
| `belt.h` | `beltKRP_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltKRPStart` | pending |  |
| `belt.h` | `beltKRPStepG` | pending |  |
| `belt.h` | `beltKRP` | pending |  |
| `belt.h` | `beltHMAC_keep` | excluded | C storage sizing / scratch memory |
| `belt.h` | `beltHMACStart` | pending |  |
| `belt.h` | `beltHMACStepA` | pending |  |
| `belt.h` | `beltHMACStepG` | pending |  |
| `belt.h` | `beltHMACStepG2` | pending |  |
| `belt.h` | `beltHMACStepV` | pending |  |
| `belt.h` | `beltHMACStepV2` | pending |  |
| `belt.h` | `beltHMAC` | pending |  |
| `belt.h` | `beltPBKDF2` | pending |  |
| `bign.h` | `bignParamsStd` | pending |  |
| `bign.h` | `bignParamsVal` | pending |  |
| `bign.h` | `bignParamsGen` | pending |  |
| `bign.h` | `bignParamsEnc` | pending |  |
| `bign.h` | `bignParamsDec` | pending |  |
| `bign.h` | `bignOidToDER` | pending |  |
| `bign.h` | `bignKeypairGen` | pending |  |
| `bign.h` | `bignKeypairVal` | pending |  |
| `bign.h` | `bignPubkeyVal` | pending |  |
| `bign.h` | `bignPubkeyCalc` | pending |  |
| `bign.h` | `bignDH` | pending |  |
| `bign.h` | `bignSign` | pending |  |
| `bign.h` | `bignSign2` | pending |  |
| `bign.h` | `bignVerify` | pending |  |
| `bign.h` | `bignKeyWrap` | pending |  |
| `bign.h` | `bignKeyUnwrap` | pending |  |
| `bign.h` | `bignIdExtract` | pending |  |
| `bign.h` | `bignIdSign` | pending |  |
| `bign.h` | `bignIdSign2` | pending |  |
| `bign.h` | `bignIdVerify` | pending |  |
| `bign128.h` | `bign128KeypairGen` | pending |  |
| `bign128.h` | `bign128KeypairVal` | pending |  |
| `bign128.h` | `bign128PubkeyVal` | pending |  |
| `bign128.h` | `bign128PubkeyCalc` | pending |  |
| `bign128.h` | `bign128DH` | pending |  |
| `bign128.h` | `bign128Sign` | pending |  |
| `bign128.h` | `bign128Sign2` | pending |  |
| `bign128.h` | `bign128Verify` | pending |  |
| `bign128.h` | `bign128KeyWrap` | pending |  |
| `bign128.h` | `bign128KeyUnwrap` | pending |  |
| `bign192.h` | `bign192KeypairGen` | pending |  |
| `bign192.h` | `bign192KeypairVal` | pending |  |
| `bign192.h` | `bign192PubkeyVal` | pending |  |
| `bign192.h` | `bign192PubkeyCalc` | pending |  |
| `bign192.h` | `bign192DH` | pending |  |
| `bign192.h` | `bign192Sign` | pending |  |
| `bign192.h` | `bign192Sign2` | pending |  |
| `bign192.h` | `bign192Verify` | pending |  |
| `bign192.h` | `bign192KeyWrap` | pending |  |
| `bign192.h` | `bign192KeyUnwrap` | pending |  |
| `bign256.h` | `bign256KeypairGen` | pending |  |
| `bign256.h` | `bign256KeypairVal` | pending |  |
| `bign256.h` | `bign256PubkeyVal` | pending |  |
| `bign256.h` | `bign256PubkeyCalc` | pending |  |
| `bign256.h` | `bign256DH` | pending |  |
| `bign256.h` | `bign256Sign` | pending |  |
| `bign256.h` | `bign256Sign2` | pending |  |
| `bign256.h` | `bign256Verify` | pending |  |
| `bign256.h` | `bign256KeyWrap` | pending |  |
| `bign256.h` | `bign256KeyUnwrap` | pending |  |
| `bign96.h` | `bign96KeypairGen` | pending |  |
| `bign96.h` | `bign96KeypairVal` | pending |  |
| `bign96.h` | `bign96PubkeyVal` | pending |  |
| `bign96.h` | `bign96PubkeyCalc` | pending |  |
| `bign96.h` | `bign96Sign` | pending |  |
| `bign96.h` | `bign96Sign2` | pending |  |
| `bign96.h` | `bign96Verify` | pending |  |
| `botp.h` | `botpDT` | excluded | internal primitive / representation helper |
| `botp.h` | `botpCtrNext` | excluded | internal primitive / representation helper |
| `botp.h` | `botpHOTP_keep` | excluded | C storage sizing / scratch memory |
| `botp.h` | `botpHOTPStart` | pending |  |
| `botp.h` | `botpHOTPStepS` | pending |  |
| `botp.h` | `botpHOTPStepR` | pending |  |
| `botp.h` | `botpHOTPStepV` | pending |  |
| `botp.h` | `botpHOTPStepG` | pending |  |
| `botp.h` | `botpHOTPRand` | pending |  |
| `botp.h` | `botpHOTPVerify` | pending |  |
| `botp.h` | `botpTOTP_keep` | excluded | C storage sizing / scratch memory |
| `botp.h` | `botpTOTPStart` | pending |  |
| `botp.h` | `botpTOTPStepR` | pending |  |
| `botp.h` | `botpTOTPStepV` | pending |  |
| `botp.h` | `botpTOTPRand` | pending |  |
| `botp.h` | `botpTOTPVerify` | pending |  |
| `botp.h` | `botpOCRA_keep` | excluded | C storage sizing / scratch memory |
| `botp.h` | `botpOCRAStart` | pending |  |
| `botp.h` | `botpOCRAStepS` | pending |  |
| `botp.h` | `botpOCRAStepR` | pending |  |
| `botp.h` | `botpOCRAStepV` | pending |  |
| `botp.h` | `botpOCRAStepG` | pending |  |
| `botp.h` | `botpOCRARand` | pending |  |
| `botp.h` | `botpOCRAVerify` | pending |  |
| `bpki.h` | `bpkiPrivkeyWrap` | pending |  |
| `bpki.h` | `bpkiPrivkeyUnwrap` | pending |  |
| `bpki.h` | `bpkiShareWrap` | pending |  |
| `bpki.h` | `bpkiShareUnwrap` | pending |  |
| `bpki.h` | `bpkiCSRRewrap` | pending |  |
| `bpki.h` | `bpkiCSRUnwrap` | pending |  |
| `brng.h` | `brngCTR_keep` | excluded | C storage sizing / scratch memory |
| `brng.h` | `brngCTRStart` | pending |  |
| `brng.h` | `brngCTRStepR` | pending |  |
| `brng.h` | `brngCTRStepG` | pending |  |
| `brng.h` | `brngCTRRand` | pending |  |
| `brng.h` | `brngHMAC_keep` | excluded | C storage sizing / scratch memory |
| `brng.h` | `brngHMACStart` | pending |  |
| `brng.h` | `brngHMACStepR` | pending |  |
| `brng.h` | `brngHMACRand` | pending |  |
| `btok.h` | `btokPwdTransition` | pending |  |
| `btok.h` | `btokCVCCheck` | pending |  |
| `btok.h` | `btokCVCCheck2` | pending |  |
| `btok.h` | `btokCVCWrap` | pending |  |
| `btok.h` | `btokCVCUnwrap` | pending |  |
| `btok.h` | `btokCVCIss` | pending |  |
| `btok.h` | `btokCVCLen` | pending |  |
| `btok.h` | `btokCVCVal` | pending |  |
| `btok.h` | `btokCVCVal2` | pending |  |
| `btok.h` | `btokCVCMatch` | pending |  |
| `btok.h` | `btokSM_keep` | excluded | C storage sizing / scratch memory |
| `btok.h` | `btokSMStart` | pending |  |
| `btok.h` | `btokSMCtrInc` | pending |  |
| `btok.h` | `btokSMCmdWrap` | pending |  |
| `btok.h` | `btokSMCmdUnwrap` | pending |  |
| `btok.h` | `btokSMRespWrap` | pending |  |
| `btok.h` | `btokSMRespUnwrap` | pending |  |
| `btok.h` | `btokBAuthT_keep` | excluded | C storage sizing / scratch memory |
| `btok.h` | `btokBAuthTStart` | pending |  |
| `btok.h` | `btokBAuthCT_keep` | excluded | C storage sizing / scratch memory |
| `btok.h` | `btokBAuthCTStart` | pending |  |
| `btok.h` | `btokBAuthCTStep2` | pending |  |
| `btok.h` | `btokBAuthTStep3` | pending |  |
| `btok.h` | `btokBAuthCTStep4` | pending |  |
| `btok.h` | `btokBAuthTStep5` | pending |  |
| `btok.h` | `btokBAuthCTStepG` | pending |  |
| `btok.h` | `btokBAuthTStepG` | pending |  |
| `dstu.h` | `dstuParamsStd` | pending |  |
| `dstu.h` | `dstuParamsVal` | pending |  |
| `dstu.h` | `dstuPointGen` | pending |  |
| `dstu.h` | `dstuPointVal` | pending |  |
| `dstu.h` | `dstuPointCompress` | pending |  |
| `dstu.h` | `dstuPointRecover` | pending |  |
| `dstu.h` | `dstuKeypairGen` | pending |  |
| `dstu.h` | `dstuSign` | pending |  |
| `dstu.h` | `dstuVerify` | pending |  |
| `g12s.h` | `g12sParamsStd` | pending |  |
| `g12s.h` | `g12sParamsVal` | pending |  |
| `g12s.h` | `g12sKeypairGen` | pending |  |
| `g12s.h` | `g12sSign` | pending |  |
| `g12s.h` | `g12sVerify` | pending |  |
| `pfok.h` | `pfokSeedVal` | pending |  |
| `pfok.h` | `pfokSeedAdj` | pending |  |
| `pfok.h` | `pfokParamsStd` | pending |  |
| `pfok.h` | `pfokParamsGen` | pending |  |
| `pfok.h` | `pfokParamsVal` | pending |  |
| `pfok.h` | `pfokKeypairGen` | pending |  |
| `pfok.h` | `pfokPubkeyVal` | pending |  |
| `pfok.h` | `pfokPubkeyCalc` | pending |  |
| `pfok.h` | `pfokDH` | pending |  |
| `pfok.h` | `pfokMTI` | pending |  |
| `stb99.h` | `stb99SeedVal` | pending |  |
| `stb99.h` | `stb99SeedAdj` | pending |  |
| `stb99.h` | `stb99ParamsStd` | pending |  |
| `stb99.h` | `stb99ParamsGen` | pending |  |
| `stb99.h` | `stb99ParamsVal` | pending |  |
