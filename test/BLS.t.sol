// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import {BLS} from "src/BLS.sol";

import {Test} from "forge-std/Test.sol";

contract BLSGasTest is Test {
    BLS.G1 public a;
    BLS.G1 public two_a;
    BLS.G2 public b;
    BLS.G2 public two_b;

    BLS.Fp public c;
    BLS.Fp2 public d;

    function setUp() public {
        a = BLS.G1({
            x: BLS.Fp({
                a0: 31827880280837800241567138048534752271,
                a1: 88385725958748408079899006800036250932223001591707578097800747617502997169851
            }),
            y: BLS.Fp({
                a0: 11568204302792691131076548377920244452,
                a1: 114417265404584670498511149331300188430316142484413708742216858159411894806497
            })
        });

        two_a = BLS.G1({
            x: BLS.Fp({
                a0: 7242197733996535748328712642142749964,
                a1: 68359058881025037662309812493615599236526584727982460305911144244635240435534
            }),
            y: BLS.Fp({
                a0: 29796594857685216314991682485311344184,
                a1: 15707703801180799344536972897481463020503508221116934637219906840883298082088
            })
        });

        b = BLS.G2({
            x: BLS.Fp2({
                c0: BLS.Fp({
                    a0: 3045985886519456750490515843806728273,
                    a1: 89961632905173714226157479458612185649920463576279427516307505038263245192632
                }),
                c1: BLS.Fp({
                    a0: 26419286191256893424348605754143887205,
                    a1: 40446337346877272185227670183527379362551741423616556919902061939448715946878
                })
            }),
            y: BLS.Fp2({
                c0: BLS.Fp({
                    a0: 17144095208600308495026432580569150746,
                    a1: 78698209480990513415779284580404715789311803115477290401294577488850054555649
                }),
                c1: BLS.Fp({
                    a0: 8010509799087472606393075511737879449,
                    a1: 91929332261301883145239454754739358796115486554644188311284324629555800144318
                })
            })
        });

        two_b = BLS.G2({
            x: BLS.Fp2({
                c0: BLS.Fp({
                    a0: 29535472514531468370931075148515562886,
                    a1: 27026973562387468075774577558889434826328022239637661708084553636472999616595
                }),
                c1: BLS.Fp({
                    a0: 13701801595577076176438294724987195983,
                    a1: 97258544455661707600501297807343636637150892150230675507527441769020287825271
                })
            }),
            y: BLS.Fp2({
                c0: BLS.Fp({
                    a0: 5862007132934151551976681480714868344,
                    a1: 69837904514102717637662850089277065587568897178497296283784895753424223377561
                }),
                c1: BLS.Fp({
                    a0: 20505786354820410751173915056854823222,
                    a1: 74268228237046184264381163192153934811165020724594696536513744318561867189491
                })
            })
        });

        c = BLS.Fp({
            a0: 27239414479292393735521031800153035394,
            a1: 5968862193243419970145906865085273018209707590744751885916960687368335445122
        });

        d = BLS.Fp2({
            c0: BLS.Fp({
                a0: 25963951880293054839892219860787843884,
                a1: 93544524369421782770976268350062384079203560236000437277085424099451768456460
            }),
            c1: BLS.Fp({
                a0: 13431977083802194122127865652609207150,
                a1: 64733979747400375164321119645737666107318766646481095747652303673867896355314
            })
        });
    }

    function test_g1Add() public {
        BLS.G1 memory _a = a;
        uint256 gasBefore = gasleft();
        BLS.G1 memory result = BLS.g1Add(_a, _a);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result.x.a0, two_a.x.a0);
        assertEq(result.x.a1, two_a.x.a1);
        assertEq(result.y.a0, two_a.y.a0);
        assertEq(result.y.a1, two_a.y.a1);
    }

    function test_g2Add() public view {
        BLS.G2 memory _b = b;
        BLS.G2 memory result = BLS.g2Add(_b, _b);

        assertEq(result.x.c0.a0, two_b.x.c0.a0);
        assertEq(result.x.c0.a1, two_b.x.c0.a1);
        assertEq(result.x.c1.a0, two_b.x.c1.a0);
        assertEq(result.x.c1.a1, two_b.x.c1.a1);
        assertEq(result.y.c0.a0, two_b.y.c0.a0);
        assertEq(result.y.c0.a1, two_b.y.c0.a1);
        assertEq(result.y.c1.a0, two_b.y.c1.a0);
        assertEq(result.y.c1.a1, two_b.y.c1.a1);
    }

    function test_g1MSM() public view {
        BLS.G1[] memory points = new BLS.G1[](1);
        points[0] = a;
        BLS.Fr[] memory scalars = new BLS.Fr[](1);
        scalars[0] = BLS.Fr.wrap(2);
        BLS.G1 memory result = BLS.g1MSM(points, scalars);

        assertEq(result.x.a0, two_a.x.a0);
        assertEq(result.x.a1, two_a.x.a1);
        assertEq(result.y.a0, two_a.y.a0);
        assertEq(result.y.a1, two_a.y.a1);
    }

    function test_g2MSM() public view {
        BLS.G2[] memory points = new BLS.G2[](1);
        points[0] = b;
        BLS.Fr[] memory scalars = new BLS.Fr[](1);
        scalars[0] = BLS.Fr.wrap(2);
        BLS.G2 memory result = BLS.g2MSM(points, scalars);

        assertEq(result.x.c0.a0, two_b.x.c0.a0);
        assertEq(result.x.c0.a1, two_b.x.c0.a1);
        assertEq(result.x.c1.a0, two_b.x.c1.a0);
        assertEq(result.x.c1.a1, two_b.x.c1.a1);
        assertEq(result.y.c0.a0, two_b.y.c0.a0);
        assertEq(result.y.c0.a1, two_b.y.c0.a1);
        assertEq(result.y.c1.a0, two_b.y.c1.a0);
        assertEq(result.y.c1.a1, two_b.y.c1.a1);
    }

    function test_pairing() public view {
        BLS.G1[] memory g1Points = new BLS.G1[](1);
        g1Points[0] = BLS.g1Infinity();
        BLS.G2[] memory g2Points = new BLS.G2[](1);
        g2Points[0] = BLS.g2Infinity();

        bool res = BLS.pairing(g1Points, g2Points);

        assertEq(res, true);
    }

    function test_mapToG1() public view {
        BLS.Fp memory x = c;
        BLS.G1 memory result = BLS.mapToG1(x);

        assertEq(result.x.a0, 786185784121070347983762658163399044);
        assertEq(result.x.a1, 89380540412990044343987908056033957202863212073198789345757892709311155056237);
        assertEq(result.y.a0, 28177298003957344089181679898123260698);
        assertEq(result.y.a1, 19331380621916130863636770942771363227286690611344895914770029792898803944748);
    }

    function test_mapToG2() public view {
        BLS.Fp2 memory x = d;
        BLS.G2 memory result = BLS.mapToG2(x);

        assertEq(result.x.c0.a0, 22009286904455570018892449804647912186);
        assertEq(result.x.c0.a1, 15395538823415676683791197694772880263016323450987704046063237764544623690783);
        assertEq(result.x.c1.a0, 3438021707132451228940320724904256326);
        assertEq(result.x.c1.a1, 2085878387021169762863298573469303727442697640881524052072844947923628111229);
        assertEq(result.y.c0.a0, 4317738848249080262790355540224735709);
        assertEq(result.y.c0.a1, 31868704098896979875598571995394909378357895029184396075613496421352147445334);
        assertEq(result.y.c1.a0, 28194309172417342129156483021706084220);
        assertEq(result.y.c1.a1, 36893114195271250715413566596996629480862857590619783789657526334545550572607);
    }
}
