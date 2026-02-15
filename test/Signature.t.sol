// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import {BLS} from "src/BLS.sol";
import {Test} from "forge-std/Test.sol";

contract SignatureVerifier {
    /**
     * @notice Verifies a standard BLS signature.
     * @param signature The G1 point representing the signature.
     * @param pubKey The G2 point representing the public key.
     * @param messageHash The G1 point representing the mapped message hash.
     * @return isValid True if the signature is valid.
     */
    function verifySignature(BLS.G1 memory signature, BLS.G2 memory pubKey, BLS.G1 memory messageHash)
        public
        view
        returns (bool isValid)
    {
        BLS.G1[] memory a = new BLS.G1[](2);
        BLS.G2[] memory b = new BLS.G2[](2);

        a[0] = signature;
        b[0] = BLS.negG2Generator();

        a[1] = messageHash;
        b[1] = pubKey;

        return BLS.pairing(a, b);
    }
}

contract SignatureTest is Test {
    SignatureVerifier public sv;

    function setUp() public {
        sv = new SignatureVerifier();
    }

    function test_verifySignature() public view {
        BLS.G1 memory sig = BLS.G1({
            x: BLS.Fp({
                a0: 15052867350433279185507887672900708495,
                a1: 105542294752221158001625925483768074249261508056717665208675342776660996081160
            }),
            y: BLS.Fp({
                a0: 24275162560566292622850929439310621070,
                a1: 70333760992135681889167864034595215546338827521782761619308625767580482192294
            })
        });

        BLS.G1 memory messageHash = BLS.G1({
            x: BLS.Fp({
                a0: 13919666065273255091064050604637821320,
                a1: 61944715969003553186739972891436734870599810097806174464629298114059905295086
            }),
            y: BLS.Fp({
                a0: 6967451755752613909712981155731508985,
                a1: 49554902397668812671104708030863415382726562095153822807202659138942561613960
            })
        });

        BLS.G2 memory pubKey = BLS.G2({
            x: BLS.Fp2({
                c0: BLS.Fp({
                    a0: 4966396196287933027645316476351538762,
                    a1: 111559972849641096358824503562434732338057037850586742204217844242160868650471
                }),
                c1: BLS.Fp({
                    a0: 949398680275914243467827858695633304,
                    a1: 47249849790110312966700521972954567023041975432452158830649060797135948355624
                })
            }),
            y: BLS.Fp2({
                c0: BLS.Fp({
                    a0: 31860401333269431635988593352944370207,
                    a1: 44689495002327653204372427785907139562381845404070943670365045164515879292954
                }),
                c1: BLS.Fp({
                    a0: 20216194607073193901947549147713446585,
                    a1: 72523505450424526541297462755492811486345562805199550154035685788566222090756
                })
            })
        });

        bool isValid = sv.verifySignature(sig, pubKey, messageHash);

        assertTrue(isValid);
    }
}
