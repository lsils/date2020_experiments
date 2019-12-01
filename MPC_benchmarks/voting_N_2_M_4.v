// Benchmark "voting_BMR_2_4" written by ABC on Tue Nov 26 13:54:11 2019

module voting_BMR_2_4 ( 
    \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] , \p_input[4] ,
    \p_input[5] , \p_input[6] , \p_input[7] , \p_input[8] , \p_input[9] ,
    \p_input[10] , \p_input[11] , \p_input[12] , \p_input[13] ,
    \p_input[14] , \p_input[15] , \p_input[16] , \p_input[17] ,
    \p_input[18] , \p_input[19] , \p_input[20] , \p_input[21] ,
    \p_input[22] , \p_input[23] , \p_input[24] , \p_input[25] ,
    \p_input[26] , \p_input[27] , \p_input[28] , \p_input[29] ,
    \p_input[30] , \p_input[31] ,
    \o[0] , \o[1]   );
  input  \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] ,
    \p_input[4] , \p_input[5] , \p_input[6] , \p_input[7] , \p_input[8] ,
    \p_input[9] , \p_input[10] , \p_input[11] , \p_input[12] ,
    \p_input[13] , \p_input[14] , \p_input[15] , \p_input[16] ,
    \p_input[17] , \p_input[18] , \p_input[19] , \p_input[20] ,
    \p_input[21] , \p_input[22] , \p_input[23] , \p_input[24] ,
    \p_input[25] , \p_input[26] , \p_input[27] , \p_input[28] ,
    \p_input[29] , \p_input[30] , \p_input[31] ;
  output \o[0] , \o[1] ;
  wire new_n35_, new_n36_, new_n37_, new_n38_, new_n39_, new_n40_, new_n41_,
    new_n42_, new_n43_, new_n44_, new_n45_, new_n46_, new_n47_, new_n48_,
    new_n49_, new_n50_, new_n51_, new_n52_, new_n53_, new_n54_, new_n55_,
    new_n56_, new_n57_, new_n58_, new_n59_, new_n60_, new_n61_, new_n62_,
    new_n63_, new_n64_, new_n65_, new_n66_, new_n67_, new_n68_, new_n69_,
    new_n70_, new_n71_, new_n72_, new_n73_, new_n74_, new_n75_, new_n76_,
    new_n77_, new_n78_, new_n79_, new_n80_, new_n81_, new_n82_, new_n83_,
    new_n84_, new_n85_, new_n86_, new_n87_, new_n88_, new_n89_, new_n90_,
    new_n91_, new_n92_, new_n93_, new_n94_, new_n95_, new_n96_, new_n97_,
    new_n98_, new_n99_, new_n100_, new_n101_, new_n102_, new_n103_,
    new_n104_, new_n105_, new_n106_, new_n107_, new_n108_, new_n109_,
    new_n110_, new_n111_, new_n112_, new_n113_, new_n114_, new_n115_,
    new_n116_, new_n117_, new_n118_, new_n119_, new_n120_, new_n121_,
    new_n122_, new_n123_, new_n124_, new_n125_, new_n126_, new_n127_,
    new_n128_, new_n129_, new_n130_, new_n131_, new_n132_, new_n133_,
    new_n134_, new_n135_, new_n136_, new_n137_, new_n138_, new_n139_,
    new_n140_, new_n141_, new_n142_, new_n143_, new_n144_, new_n145_,
    new_n146_, new_n147_, new_n148_, new_n149_, new_n150_, new_n151_,
    new_n152_, new_n153_, new_n154_, new_n155_, new_n156_, new_n157_,
    new_n158_, new_n159_, new_n160_, new_n161_, new_n162_, new_n163_,
    new_n164_, new_n165_, new_n166_, new_n167_, new_n168_, new_n169_,
    new_n170_, new_n171_, new_n172_, new_n173_, new_n174_, new_n175_,
    new_n176_, new_n177_, new_n178_, new_n179_, new_n180_, new_n181_,
    new_n182_, new_n183_, new_n184_, new_n185_, new_n186_, new_n187_,
    new_n188_, new_n189_, new_n190_, new_n191_, new_n192_, new_n193_,
    new_n194_, new_n195_, new_n196_, new_n197_, new_n198_, new_n199_,
    new_n200_, new_n201_, new_n202_, new_n203_, new_n204_, new_n205_,
    new_n206_, new_n207_, new_n208_, new_n209_, new_n210_, new_n211_,
    new_n212_, new_n213_, new_n214_, new_n215_, new_n216_, new_n217_,
    new_n218_, new_n219_, new_n220_, new_n221_, new_n222_, new_n223_,
    new_n224_, new_n225_, new_n226_, new_n227_, new_n228_, new_n229_,
    new_n230_, new_n231_, new_n232_, new_n233_, new_n234_, new_n235_,
    new_n236_, new_n237_, new_n238_, new_n239_, new_n240_, new_n241_,
    new_n242_, new_n243_, new_n244_, new_n245_, new_n246_, new_n247_,
    new_n248_, new_n249_, new_n250_, new_n251_, new_n252_, new_n253_,
    new_n254_, new_n255_, new_n256_, new_n257_, new_n258_, new_n259_,
    new_n260_, new_n261_, new_n262_, new_n263_, new_n264_, new_n265_,
    new_n266_, new_n267_, new_n268_, new_n269_, new_n270_, new_n271_,
    new_n272_, new_n273_, new_n274_, new_n275_, new_n276_, new_n277_,
    new_n278_, new_n279_, new_n280_, new_n281_, new_n282_, new_n283_,
    new_n284_, new_n285_, new_n286_, new_n287_, new_n288_, new_n289_,
    new_n290_, new_n291_, new_n292_, new_n293_, new_n294_, new_n295_,
    new_n296_, new_n297_, new_n298_, new_n299_, new_n300_, new_n301_,
    new_n302_, new_n303_, new_n304_, new_n305_, new_n306_, new_n307_,
    new_n308_, new_n309_, new_n310_, new_n311_, new_n312_, new_n313_,
    new_n314_, new_n315_, new_n316_, new_n317_, new_n318_, new_n319_,
    new_n320_, new_n321_, new_n322_, new_n323_, new_n324_, new_n325_,
    new_n326_, new_n327_, new_n328_, new_n329_, new_n330_, new_n331_,
    new_n332_, new_n333_, new_n334_, new_n335_, new_n336_, new_n337_,
    new_n338_, new_n339_, new_n340_, new_n341_, new_n342_, new_n343_,
    new_n344_, new_n345_, new_n346_, new_n347_, new_n348_, new_n349_,
    new_n350_, new_n351_, new_n352_, new_n353_, new_n354_, new_n355_,
    new_n356_, new_n357_, new_n358_, new_n359_, new_n360_, new_n361_,
    new_n362_, new_n363_, new_n364_, new_n365_, new_n366_, new_n367_,
    new_n368_, new_n369_, new_n370_, new_n371_, new_n372_, new_n373_,
    new_n374_, new_n375_, new_n376_, new_n377_, new_n378_, new_n379_,
    new_n380_, new_n381_, new_n382_, new_n383_, new_n384_, new_n385_,
    new_n386_, new_n387_, new_n388_, new_n389_, new_n390_, new_n391_,
    new_n392_, new_n393_, new_n394_, new_n395_, new_n396_, new_n397_,
    new_n398_, new_n399_, new_n400_, new_n401_, new_n402_, new_n403_,
    new_n404_, new_n405_, new_n406_, new_n407_, new_n408_, new_n409_,
    new_n410_, new_n411_, new_n412_, new_n413_, new_n414_, new_n415_,
    new_n416_, new_n417_, new_n418_, new_n419_, new_n420_, new_n421_,
    new_n422_, new_n423_, new_n424_, new_n425_, new_n426_, new_n427_,
    new_n428_, new_n429_, new_n430_, new_n431_, new_n432_, new_n433_,
    new_n434_, new_n435_, new_n436_, new_n437_, new_n438_, new_n439_,
    new_n440_, new_n441_, new_n442_, new_n443_, new_n444_, new_n445_,
    new_n446_, new_n447_, new_n448_, new_n449_, new_n450_, new_n451_,
    new_n452_, new_n453_, new_n454_, new_n455_, new_n456_, new_n457_,
    new_n458_, new_n459_, new_n460_, new_n461_, new_n462_, new_n463_,
    new_n464_, new_n465_, new_n466_, new_n467_, new_n468_, new_n469_,
    new_n470_, new_n471_, new_n472_, new_n473_, new_n474_, new_n475_,
    new_n476_, new_n477_, new_n478_, new_n479_, new_n480_, new_n481_,
    new_n482_, new_n483_, new_n484_, new_n485_, new_n486_, new_n487_,
    new_n488_, new_n489_, new_n490_, new_n491_, new_n492_, new_n493_,
    new_n494_, new_n495_, new_n496_, new_n497_, new_n498_, new_n499_,
    new_n500_, new_n501_, new_n502_, new_n503_, new_n504_, new_n505_,
    new_n506_, new_n507_, new_n508_, new_n509_, new_n510_, new_n511_,
    new_n512_, new_n513_, new_n514_, new_n515_, new_n516_, new_n517_,
    new_n518_, new_n519_, new_n520_, new_n521_, new_n522_, new_n523_,
    new_n524_, new_n525_, new_n526_, new_n527_, new_n528_, new_n529_,
    new_n530_, new_n531_, new_n532_, new_n533_, new_n534_, new_n535_,
    new_n536_, new_n537_, new_n538_, new_n539_, new_n540_, new_n541_,
    new_n542_, new_n543_, new_n544_, new_n545_, new_n546_, new_n547_,
    new_n548_, new_n550_, new_n551_;
  assign new_n35_ = \p_input[2]  & ~\p_input[3] ;
  assign new_n36_ = \p_input[18]  & ~\p_input[19] ;
  assign new_n37_ = \p_input[30]  & ~\p_input[31] ;
  assign new_n38_ = \p_input[28]  & ~\p_input[29] ;
  assign new_n39_ = \p_input[26]  & ~\p_input[27] ;
  assign new_n40_ = ~new_n38_ & ~new_n39_;
  assign new_n41_ = new_n38_ & new_n39_;
  assign new_n42_ = ~new_n40_ & ~new_n41_;
  assign new_n43_ = new_n37_ & ~new_n42_;
  assign new_n44_ = ~new_n37_ & new_n42_;
  assign new_n45_ = ~new_n43_ & ~new_n44_;
  assign new_n46_ = new_n36_ & ~new_n45_;
  assign new_n47_ = ~new_n36_ & new_n45_;
  assign new_n48_ = ~new_n46_ & ~new_n47_;
  assign new_n49_ = \p_input[24]  & ~\p_input[25] ;
  assign new_n50_ = \p_input[22]  & ~\p_input[23] ;
  assign new_n51_ = \p_input[20]  & ~\p_input[21] ;
  assign new_n52_ = new_n50_ & new_n51_;
  assign new_n53_ = ~new_n50_ & ~new_n51_;
  assign new_n54_ = ~new_n52_ & ~new_n53_;
  assign new_n55_ = new_n49_ & ~new_n54_;
  assign new_n56_ = ~new_n49_ & new_n54_;
  assign new_n57_ = ~new_n55_ & ~new_n56_;
  assign new_n58_ = new_n48_ & ~new_n57_;
  assign new_n59_ = ~new_n48_ & new_n57_;
  assign new_n60_ = ~new_n58_ & ~new_n59_;
  assign new_n61_ = new_n35_ & new_n60_;
  assign new_n62_ = \p_input[4]  & ~\p_input[5] ;
  assign new_n63_ = \p_input[16]  & ~\p_input[17] ;
  assign new_n64_ = \p_input[14]  & ~\p_input[15] ;
  assign new_n65_ = \p_input[12]  & ~\p_input[13] ;
  assign new_n66_ = new_n64_ & new_n65_;
  assign new_n67_ = ~new_n64_ & ~new_n65_;
  assign new_n68_ = ~new_n66_ & ~new_n67_;
  assign new_n69_ = new_n63_ & ~new_n68_;
  assign new_n70_ = ~new_n63_ & new_n68_;
  assign new_n71_ = ~new_n69_ & ~new_n70_;
  assign new_n72_ = ~new_n62_ & new_n71_;
  assign new_n73_ = new_n62_ & ~new_n71_;
  assign new_n74_ = ~new_n72_ & ~new_n73_;
  assign new_n75_ = \p_input[10]  & ~\p_input[11] ;
  assign new_n76_ = \p_input[8]  & ~\p_input[9] ;
  assign new_n77_ = \p_input[6]  & ~\p_input[7] ;
  assign new_n78_ = new_n76_ & new_n77_;
  assign new_n79_ = ~new_n76_ & ~new_n77_;
  assign new_n80_ = ~new_n78_ & ~new_n79_;
  assign new_n81_ = new_n75_ & ~new_n80_;
  assign new_n82_ = ~new_n75_ & new_n80_;
  assign new_n83_ = ~new_n81_ & ~new_n82_;
  assign new_n84_ = new_n74_ & ~new_n83_;
  assign new_n85_ = ~new_n74_ & new_n83_;
  assign new_n86_ = ~new_n84_ & ~new_n85_;
  assign new_n87_ = ~new_n35_ & ~new_n60_;
  assign new_n88_ = ~new_n61_ & ~new_n87_;
  assign new_n89_ = new_n86_ & new_n88_;
  assign new_n90_ = ~new_n61_ & ~new_n89_;
  assign new_n91_ = ~new_n46_ & ~new_n58_;
  assign new_n92_ = ~new_n37_ & ~new_n41_;
  assign new_n93_ = ~new_n40_ & ~new_n92_;
  assign new_n94_ = new_n91_ & ~new_n93_;
  assign new_n95_ = ~new_n91_ & new_n93_;
  assign new_n96_ = ~new_n94_ & ~new_n95_;
  assign new_n97_ = ~new_n49_ & ~new_n52_;
  assign new_n98_ = ~new_n53_ & ~new_n97_;
  assign new_n99_ = new_n96_ & new_n98_;
  assign new_n100_ = ~new_n96_ & ~new_n98_;
  assign new_n101_ = ~new_n99_ & ~new_n100_;
  assign new_n102_ = new_n90_ & ~new_n101_;
  assign new_n103_ = ~new_n90_ & new_n101_;
  assign new_n104_ = ~new_n73_ & ~new_n84_;
  assign new_n105_ = ~new_n63_ & ~new_n66_;
  assign new_n106_ = ~new_n67_ & ~new_n105_;
  assign new_n107_ = ~new_n104_ & new_n106_;
  assign new_n108_ = new_n104_ & ~new_n106_;
  assign new_n109_ = ~new_n107_ & ~new_n108_;
  assign new_n110_ = ~new_n75_ & ~new_n78_;
  assign new_n111_ = ~new_n79_ & ~new_n110_;
  assign new_n112_ = new_n109_ & new_n111_;
  assign new_n113_ = ~new_n109_ & ~new_n111_;
  assign new_n114_ = ~new_n112_ & ~new_n113_;
  assign new_n115_ = ~new_n103_ & ~new_n114_;
  assign new_n116_ = ~new_n102_ & ~new_n115_;
  assign new_n117_ = ~new_n95_ & ~new_n99_;
  assign new_n118_ = ~new_n116_ & new_n117_;
  assign new_n119_ = new_n116_ & ~new_n117_;
  assign new_n120_ = ~new_n118_ & ~new_n119_;
  assign new_n121_ = ~new_n107_ & ~new_n112_;
  assign new_n122_ = new_n120_ & new_n121_;
  assign new_n123_ = ~new_n118_ & ~new_n122_;
  assign new_n124_ = ~new_n120_ & ~new_n121_;
  assign new_n125_ = ~new_n122_ & ~new_n124_;
  assign new_n126_ = \p_input[0]  & ~\p_input[1] ;
  assign new_n127_ = ~new_n86_ & ~new_n88_;
  assign new_n128_ = ~new_n89_ & ~new_n127_;
  assign new_n129_ = new_n126_ & new_n128_;
  assign new_n130_ = ~new_n102_ & ~new_n103_;
  assign new_n131_ = ~new_n114_ & new_n130_;
  assign new_n132_ = new_n114_ & ~new_n130_;
  assign new_n133_ = ~new_n131_ & ~new_n132_;
  assign new_n134_ = new_n129_ & ~new_n133_;
  assign new_n135_ = ~new_n125_ & new_n134_;
  assign new_n136_ = new_n123_ & new_n135_;
  assign new_n137_ = ~\p_input[28]  & ~\p_input[29] ;
  assign new_n138_ = ~\p_input[26]  & ~\p_input[27] ;
  assign new_n139_ = ~new_n137_ & ~new_n138_;
  assign new_n140_ = ~\p_input[30]  & ~\p_input[31] ;
  assign new_n141_ = new_n137_ & new_n138_;
  assign new_n142_ = ~new_n139_ & ~new_n141_;
  assign new_n143_ = ~new_n140_ & new_n142_;
  assign new_n144_ = ~new_n139_ & ~new_n143_;
  assign new_n145_ = new_n140_ & ~new_n142_;
  assign new_n146_ = ~new_n143_ & ~new_n145_;
  assign new_n147_ = ~\p_input[18]  & ~\p_input[19] ;
  assign new_n148_ = ~new_n146_ & new_n147_;
  assign new_n149_ = new_n146_ & ~new_n147_;
  assign new_n150_ = ~\p_input[24]  & ~\p_input[25] ;
  assign new_n151_ = ~\p_input[22]  & ~\p_input[23] ;
  assign new_n152_ = ~\p_input[20]  & ~\p_input[21] ;
  assign new_n153_ = ~new_n151_ & ~new_n152_;
  assign new_n154_ = new_n151_ & new_n152_;
  assign new_n155_ = ~new_n153_ & ~new_n154_;
  assign new_n156_ = ~new_n150_ & new_n155_;
  assign new_n157_ = new_n150_ & ~new_n155_;
  assign new_n158_ = ~new_n156_ & ~new_n157_;
  assign new_n159_ = ~new_n149_ & ~new_n158_;
  assign new_n160_ = ~new_n148_ & ~new_n159_;
  assign new_n161_ = ~new_n144_ & new_n160_;
  assign new_n162_ = ~new_n153_ & ~new_n156_;
  assign new_n163_ = new_n144_ & ~new_n160_;
  assign new_n164_ = ~new_n161_ & ~new_n163_;
  assign new_n165_ = ~new_n162_ & new_n164_;
  assign new_n166_ = ~new_n161_ & ~new_n165_;
  assign new_n167_ = new_n162_ & ~new_n164_;
  assign new_n168_ = ~new_n165_ & ~new_n167_;
  assign new_n169_ = ~\p_input[2]  & ~\p_input[3] ;
  assign new_n170_ = ~new_n148_ & ~new_n149_;
  assign new_n171_ = new_n158_ & new_n170_;
  assign new_n172_ = ~new_n158_ & ~new_n170_;
  assign new_n173_ = ~new_n171_ & ~new_n172_;
  assign new_n174_ = new_n169_ & ~new_n173_;
  assign new_n175_ = ~new_n169_ & new_n173_;
  assign new_n176_ = ~\p_input[10]  & ~\p_input[11] ;
  assign new_n177_ = ~\p_input[8]  & ~\p_input[9] ;
  assign new_n178_ = ~\p_input[6]  & ~\p_input[7] ;
  assign new_n179_ = ~new_n177_ & ~new_n178_;
  assign new_n180_ = new_n177_ & new_n178_;
  assign new_n181_ = ~new_n179_ & ~new_n180_;
  assign new_n182_ = ~new_n176_ & new_n181_;
  assign new_n183_ = new_n176_ & ~new_n181_;
  assign new_n184_ = ~new_n182_ & ~new_n183_;
  assign new_n185_ = ~\p_input[16]  & ~\p_input[17] ;
  assign new_n186_ = ~\p_input[14]  & ~\p_input[15] ;
  assign new_n187_ = ~\p_input[12]  & ~\p_input[13] ;
  assign new_n188_ = ~new_n186_ & ~new_n187_;
  assign new_n189_ = new_n186_ & new_n187_;
  assign new_n190_ = ~new_n188_ & ~new_n189_;
  assign new_n191_ = ~new_n185_ & new_n190_;
  assign new_n192_ = new_n185_ & ~new_n190_;
  assign new_n193_ = ~new_n191_ & ~new_n192_;
  assign new_n194_ = ~\p_input[4]  & ~\p_input[5] ;
  assign new_n195_ = new_n193_ & ~new_n194_;
  assign new_n196_ = ~new_n193_ & new_n194_;
  assign new_n197_ = ~new_n195_ & ~new_n196_;
  assign new_n198_ = new_n184_ & new_n197_;
  assign new_n199_ = ~new_n184_ & ~new_n197_;
  assign new_n200_ = ~new_n198_ & ~new_n199_;
  assign new_n201_ = ~new_n175_ & ~new_n200_;
  assign new_n202_ = ~new_n174_ & ~new_n201_;
  assign new_n203_ = ~new_n168_ & ~new_n202_;
  assign new_n204_ = new_n168_ & new_n202_;
  assign new_n205_ = ~new_n188_ & ~new_n191_;
  assign new_n206_ = ~new_n195_ & ~new_n198_;
  assign new_n207_ = new_n205_ & new_n206_;
  assign new_n208_ = ~new_n205_ & ~new_n206_;
  assign new_n209_ = ~new_n207_ & ~new_n208_;
  assign new_n210_ = ~new_n179_ & ~new_n182_;
  assign new_n211_ = ~new_n209_ & new_n210_;
  assign new_n212_ = new_n209_ & ~new_n210_;
  assign new_n213_ = ~new_n211_ & ~new_n212_;
  assign new_n214_ = ~new_n204_ & ~new_n213_;
  assign new_n215_ = ~new_n203_ & ~new_n214_;
  assign new_n216_ = new_n166_ & ~new_n215_;
  assign new_n217_ = ~\p_input[0]  & ~\p_input[1] ;
  assign new_n218_ = ~new_n174_ & ~new_n175_;
  assign new_n219_ = new_n200_ & new_n218_;
  assign new_n220_ = ~new_n200_ & ~new_n218_;
  assign new_n221_ = ~new_n219_ & ~new_n220_;
  assign new_n222_ = new_n217_ & ~new_n221_;
  assign new_n223_ = ~new_n203_ & ~new_n204_;
  assign new_n224_ = ~new_n213_ & new_n223_;
  assign new_n225_ = new_n213_ & ~new_n223_;
  assign new_n226_ = ~new_n224_ & ~new_n225_;
  assign new_n227_ = new_n222_ & new_n226_;
  assign new_n228_ = ~new_n208_ & ~new_n212_;
  assign new_n229_ = ~new_n166_ & new_n215_;
  assign new_n230_ = ~new_n216_ & ~new_n229_;
  assign new_n231_ = new_n228_ & new_n230_;
  assign new_n232_ = ~new_n228_ & ~new_n230_;
  assign new_n233_ = ~new_n231_ & ~new_n232_;
  assign new_n234_ = new_n227_ & new_n233_;
  assign new_n235_ = new_n216_ & new_n234_;
  assign new_n236_ = new_n136_ & ~new_n235_;
  assign new_n237_ = ~new_n136_ & new_n235_;
  assign new_n238_ = ~new_n123_ & ~new_n135_;
  assign new_n239_ = ~new_n136_ & ~new_n238_;
  assign new_n240_ = ~new_n216_ & ~new_n231_;
  assign new_n241_ = ~new_n234_ & new_n240_;
  assign new_n242_ = ~new_n235_ & ~new_n241_;
  assign new_n243_ = ~new_n239_ & new_n242_;
  assign new_n244_ = new_n239_ & ~new_n242_;
  assign new_n245_ = ~new_n227_ & ~new_n233_;
  assign new_n246_ = ~new_n234_ & ~new_n245_;
  assign new_n247_ = ~new_n217_ & new_n221_;
  assign new_n248_ = ~new_n222_ & ~new_n247_;
  assign new_n249_ = ~new_n126_ & ~new_n128_;
  assign new_n250_ = ~new_n129_ & ~new_n249_;
  assign new_n251_ = new_n248_ & ~new_n250_;
  assign new_n252_ = new_n226_ & new_n251_;
  assign new_n253_ = ~new_n129_ & new_n133_;
  assign new_n254_ = ~new_n134_ & ~new_n253_;
  assign new_n255_ = ~new_n222_ & ~new_n226_;
  assign new_n256_ = ~new_n227_ & ~new_n255_;
  assign new_n257_ = ~new_n251_ & ~new_n256_;
  assign new_n258_ = ~new_n254_ & ~new_n257_;
  assign new_n259_ = ~new_n252_ & ~new_n258_;
  assign new_n260_ = new_n246_ & ~new_n259_;
  assign new_n261_ = new_n125_ & ~new_n134_;
  assign new_n262_ = ~new_n135_ & ~new_n261_;
  assign new_n263_ = ~new_n246_ & new_n259_;
  assign new_n264_ = ~new_n262_ & ~new_n263_;
  assign new_n265_ = ~new_n260_ & ~new_n264_;
  assign new_n266_ = ~new_n244_ & ~new_n265_;
  assign new_n267_ = ~new_n237_ & ~new_n243_;
  assign new_n268_ = ~new_n266_ & new_n267_;
  assign new_n269_ = ~new_n236_ & ~new_n268_;
  assign new_n270_ = ~new_n136_ & ~new_n235_;
  assign new_n271_ = ~\p_input[18]  & \p_input[19] ;
  assign new_n272_ = ~\p_input[30]  & \p_input[31] ;
  assign new_n273_ = ~\p_input[28]  & \p_input[29] ;
  assign new_n274_ = ~\p_input[26]  & \p_input[27] ;
  assign new_n275_ = ~new_n273_ & ~new_n274_;
  assign new_n276_ = new_n273_ & new_n274_;
  assign new_n277_ = ~new_n275_ & ~new_n276_;
  assign new_n278_ = new_n272_ & ~new_n277_;
  assign new_n279_ = ~new_n272_ & new_n277_;
  assign new_n280_ = ~new_n278_ & ~new_n279_;
  assign new_n281_ = new_n271_ & ~new_n280_;
  assign new_n282_ = ~new_n271_ & new_n280_;
  assign new_n283_ = ~\p_input[24]  & \p_input[25] ;
  assign new_n284_ = ~\p_input[22]  & \p_input[23] ;
  assign new_n285_ = ~\p_input[20]  & \p_input[21] ;
  assign new_n286_ = ~new_n284_ & ~new_n285_;
  assign new_n287_ = new_n284_ & new_n285_;
  assign new_n288_ = ~new_n286_ & ~new_n287_;
  assign new_n289_ = new_n283_ & ~new_n288_;
  assign new_n290_ = ~new_n283_ & new_n288_;
  assign new_n291_ = ~new_n289_ & ~new_n290_;
  assign new_n292_ = ~new_n282_ & ~new_n291_;
  assign new_n293_ = ~new_n281_ & ~new_n292_;
  assign new_n294_ = ~new_n272_ & ~new_n276_;
  assign new_n295_ = ~new_n275_ & ~new_n294_;
  assign new_n296_ = ~new_n293_ & new_n295_;
  assign new_n297_ = new_n293_ & ~new_n295_;
  assign new_n298_ = ~new_n296_ & ~new_n297_;
  assign new_n299_ = ~new_n283_ & ~new_n287_;
  assign new_n300_ = ~new_n286_ & ~new_n299_;
  assign new_n301_ = new_n298_ & new_n300_;
  assign new_n302_ = ~new_n296_ & ~new_n301_;
  assign new_n303_ = ~new_n298_ & ~new_n300_;
  assign new_n304_ = ~new_n301_ & ~new_n303_;
  assign new_n305_ = ~\p_input[2]  & \p_input[3] ;
  assign new_n306_ = ~new_n281_ & ~new_n282_;
  assign new_n307_ = new_n291_ & new_n306_;
  assign new_n308_ = ~new_n291_ & ~new_n306_;
  assign new_n309_ = ~new_n307_ & ~new_n308_;
  assign new_n310_ = new_n305_ & ~new_n309_;
  assign new_n311_ = ~new_n305_ & new_n309_;
  assign new_n312_ = ~\p_input[4]  & \p_input[5] ;
  assign new_n313_ = ~\p_input[16]  & \p_input[17] ;
  assign new_n314_ = ~\p_input[14]  & \p_input[15] ;
  assign new_n315_ = ~\p_input[12]  & \p_input[13] ;
  assign new_n316_ = new_n314_ & new_n315_;
  assign new_n317_ = ~new_n314_ & ~new_n315_;
  assign new_n318_ = ~new_n316_ & ~new_n317_;
  assign new_n319_ = new_n313_ & ~new_n318_;
  assign new_n320_ = ~new_n313_ & new_n318_;
  assign new_n321_ = ~new_n319_ & ~new_n320_;
  assign new_n322_ = new_n312_ & ~new_n321_;
  assign new_n323_ = ~new_n312_ & new_n321_;
  assign new_n324_ = ~new_n322_ & ~new_n323_;
  assign new_n325_ = ~\p_input[10]  & \p_input[11] ;
  assign new_n326_ = ~\p_input[8]  & \p_input[9] ;
  assign new_n327_ = ~\p_input[6]  & \p_input[7] ;
  assign new_n328_ = new_n326_ & new_n327_;
  assign new_n329_ = ~new_n326_ & ~new_n327_;
  assign new_n330_ = ~new_n328_ & ~new_n329_;
  assign new_n331_ = new_n325_ & ~new_n330_;
  assign new_n332_ = ~new_n325_ & new_n330_;
  assign new_n333_ = ~new_n331_ & ~new_n332_;
  assign new_n334_ = new_n324_ & ~new_n333_;
  assign new_n335_ = ~new_n324_ & new_n333_;
  assign new_n336_ = ~new_n334_ & ~new_n335_;
  assign new_n337_ = ~new_n311_ & new_n336_;
  assign new_n338_ = ~new_n310_ & ~new_n337_;
  assign new_n339_ = new_n304_ & ~new_n338_;
  assign new_n340_ = ~new_n304_ & new_n338_;
  assign new_n341_ = ~new_n322_ & ~new_n334_;
  assign new_n342_ = ~new_n313_ & ~new_n316_;
  assign new_n343_ = ~new_n317_ & ~new_n342_;
  assign new_n344_ = new_n341_ & ~new_n343_;
  assign new_n345_ = ~new_n341_ & new_n343_;
  assign new_n346_ = ~new_n344_ & ~new_n345_;
  assign new_n347_ = ~new_n325_ & ~new_n328_;
  assign new_n348_ = ~new_n329_ & ~new_n347_;
  assign new_n349_ = new_n346_ & new_n348_;
  assign new_n350_ = ~new_n346_ & ~new_n348_;
  assign new_n351_ = ~new_n349_ & ~new_n350_;
  assign new_n352_ = ~new_n340_ & new_n351_;
  assign new_n353_ = ~new_n339_ & ~new_n352_;
  assign new_n354_ = new_n302_ & new_n353_;
  assign new_n355_ = ~new_n302_ & ~new_n353_;
  assign new_n356_ = ~new_n354_ & ~new_n355_;
  assign new_n357_ = ~new_n345_ & ~new_n349_;
  assign new_n358_ = new_n356_ & new_n357_;
  assign new_n359_ = ~new_n356_ & ~new_n357_;
  assign new_n360_ = ~new_n358_ & ~new_n359_;
  assign new_n361_ = ~\p_input[0]  & \p_input[1] ;
  assign new_n362_ = ~new_n310_ & ~new_n311_;
  assign new_n363_ = new_n336_ & new_n362_;
  assign new_n364_ = ~new_n336_ & ~new_n362_;
  assign new_n365_ = ~new_n363_ & ~new_n364_;
  assign new_n366_ = new_n361_ & new_n365_;
  assign new_n367_ = ~new_n339_ & ~new_n340_;
  assign new_n368_ = new_n351_ & new_n367_;
  assign new_n369_ = ~new_n351_ & ~new_n367_;
  assign new_n370_ = ~new_n368_ & ~new_n369_;
  assign new_n371_ = new_n366_ & new_n370_;
  assign new_n372_ = ~new_n360_ & new_n371_;
  assign new_n373_ = ~new_n354_ & ~new_n358_;
  assign new_n374_ = new_n372_ & new_n373_;
  assign new_n375_ = \p_input[2]  & \p_input[3] ;
  assign new_n376_ = \p_input[18]  & \p_input[19] ;
  assign new_n377_ = \p_input[30]  & \p_input[31] ;
  assign new_n378_ = \p_input[28]  & \p_input[29] ;
  assign new_n379_ = \p_input[26]  & \p_input[27] ;
  assign new_n380_ = ~new_n378_ & ~new_n379_;
  assign new_n381_ = new_n378_ & new_n379_;
  assign new_n382_ = ~new_n380_ & ~new_n381_;
  assign new_n383_ = new_n377_ & ~new_n382_;
  assign new_n384_ = ~new_n377_ & new_n382_;
  assign new_n385_ = ~new_n383_ & ~new_n384_;
  assign new_n386_ = new_n376_ & ~new_n385_;
  assign new_n387_ = ~new_n376_ & new_n385_;
  assign new_n388_ = ~new_n386_ & ~new_n387_;
  assign new_n389_ = \p_input[24]  & \p_input[25] ;
  assign new_n390_ = \p_input[22]  & \p_input[23] ;
  assign new_n391_ = \p_input[20]  & \p_input[21] ;
  assign new_n392_ = new_n390_ & new_n391_;
  assign new_n393_ = ~new_n390_ & ~new_n391_;
  assign new_n394_ = ~new_n392_ & ~new_n393_;
  assign new_n395_ = new_n389_ & ~new_n394_;
  assign new_n396_ = ~new_n389_ & new_n394_;
  assign new_n397_ = ~new_n395_ & ~new_n396_;
  assign new_n398_ = new_n388_ & ~new_n397_;
  assign new_n399_ = ~new_n388_ & new_n397_;
  assign new_n400_ = ~new_n398_ & ~new_n399_;
  assign new_n401_ = new_n375_ & new_n400_;
  assign new_n402_ = \p_input[4]  & \p_input[5] ;
  assign new_n403_ = \p_input[16]  & \p_input[17] ;
  assign new_n404_ = \p_input[14]  & \p_input[15] ;
  assign new_n405_ = \p_input[12]  & \p_input[13] ;
  assign new_n406_ = new_n404_ & new_n405_;
  assign new_n407_ = ~new_n404_ & ~new_n405_;
  assign new_n408_ = ~new_n406_ & ~new_n407_;
  assign new_n409_ = new_n403_ & ~new_n408_;
  assign new_n410_ = ~new_n403_ & new_n408_;
  assign new_n411_ = ~new_n409_ & ~new_n410_;
  assign new_n412_ = ~new_n402_ & new_n411_;
  assign new_n413_ = new_n402_ & ~new_n411_;
  assign new_n414_ = ~new_n412_ & ~new_n413_;
  assign new_n415_ = \p_input[10]  & \p_input[11] ;
  assign new_n416_ = \p_input[8]  & \p_input[9] ;
  assign new_n417_ = \p_input[6]  & \p_input[7] ;
  assign new_n418_ = new_n416_ & new_n417_;
  assign new_n419_ = ~new_n416_ & ~new_n417_;
  assign new_n420_ = ~new_n418_ & ~new_n419_;
  assign new_n421_ = new_n415_ & ~new_n420_;
  assign new_n422_ = ~new_n415_ & new_n420_;
  assign new_n423_ = ~new_n421_ & ~new_n422_;
  assign new_n424_ = new_n414_ & ~new_n423_;
  assign new_n425_ = ~new_n414_ & new_n423_;
  assign new_n426_ = ~new_n424_ & ~new_n425_;
  assign new_n427_ = ~new_n375_ & ~new_n400_;
  assign new_n428_ = ~new_n401_ & ~new_n427_;
  assign new_n429_ = new_n426_ & new_n428_;
  assign new_n430_ = ~new_n401_ & ~new_n429_;
  assign new_n431_ = ~new_n386_ & ~new_n398_;
  assign new_n432_ = ~new_n377_ & ~new_n381_;
  assign new_n433_ = ~new_n380_ & ~new_n432_;
  assign new_n434_ = new_n431_ & ~new_n433_;
  assign new_n435_ = ~new_n431_ & new_n433_;
  assign new_n436_ = ~new_n434_ & ~new_n435_;
  assign new_n437_ = ~new_n389_ & ~new_n392_;
  assign new_n438_ = ~new_n393_ & ~new_n437_;
  assign new_n439_ = new_n436_ & new_n438_;
  assign new_n440_ = ~new_n436_ & ~new_n438_;
  assign new_n441_ = ~new_n439_ & ~new_n440_;
  assign new_n442_ = new_n430_ & ~new_n441_;
  assign new_n443_ = ~new_n430_ & new_n441_;
  assign new_n444_ = ~new_n413_ & ~new_n424_;
  assign new_n445_ = ~new_n403_ & ~new_n406_;
  assign new_n446_ = ~new_n407_ & ~new_n445_;
  assign new_n447_ = ~new_n444_ & new_n446_;
  assign new_n448_ = new_n444_ & ~new_n446_;
  assign new_n449_ = ~new_n447_ & ~new_n448_;
  assign new_n450_ = ~new_n415_ & ~new_n418_;
  assign new_n451_ = ~new_n419_ & ~new_n450_;
  assign new_n452_ = new_n449_ & new_n451_;
  assign new_n453_ = ~new_n449_ & ~new_n451_;
  assign new_n454_ = ~new_n452_ & ~new_n453_;
  assign new_n455_ = ~new_n443_ & ~new_n454_;
  assign new_n456_ = ~new_n442_ & ~new_n455_;
  assign new_n457_ = ~new_n435_ & ~new_n439_;
  assign new_n458_ = ~new_n456_ & new_n457_;
  assign new_n459_ = new_n456_ & ~new_n457_;
  assign new_n460_ = ~new_n458_ & ~new_n459_;
  assign new_n461_ = ~new_n447_ & ~new_n452_;
  assign new_n462_ = new_n460_ & new_n461_;
  assign new_n463_ = ~new_n458_ & ~new_n462_;
  assign new_n464_ = ~new_n460_ & ~new_n461_;
  assign new_n465_ = ~new_n462_ & ~new_n464_;
  assign new_n466_ = \p_input[0]  & \p_input[1] ;
  assign new_n467_ = ~new_n426_ & ~new_n428_;
  assign new_n468_ = ~new_n429_ & ~new_n467_;
  assign new_n469_ = new_n466_ & new_n468_;
  assign new_n470_ = ~new_n442_ & ~new_n443_;
  assign new_n471_ = ~new_n454_ & new_n470_;
  assign new_n472_ = new_n454_ & ~new_n470_;
  assign new_n473_ = ~new_n471_ & ~new_n472_;
  assign new_n474_ = new_n469_ & ~new_n473_;
  assign new_n475_ = ~new_n465_ & new_n474_;
  assign new_n476_ = new_n463_ & new_n475_;
  assign new_n477_ = ~new_n374_ & ~new_n476_;
  assign new_n478_ = new_n270_ & ~new_n477_;
  assign new_n479_ = ~new_n469_ & new_n473_;
  assign new_n480_ = ~new_n474_ & ~new_n479_;
  assign new_n481_ = ~new_n374_ & new_n476_;
  assign new_n482_ = new_n374_ & ~new_n476_;
  assign new_n483_ = ~new_n463_ & ~new_n475_;
  assign new_n484_ = ~new_n476_ & ~new_n483_;
  assign new_n485_ = ~new_n372_ & ~new_n373_;
  assign new_n486_ = ~new_n374_ & ~new_n485_;
  assign new_n487_ = ~new_n484_ & new_n486_;
  assign new_n488_ = new_n484_ & ~new_n486_;
  assign new_n489_ = new_n360_ & ~new_n371_;
  assign new_n490_ = ~new_n372_ & ~new_n489_;
  assign new_n491_ = ~new_n361_ & ~new_n365_;
  assign new_n492_ = ~new_n366_ & ~new_n491_;
  assign new_n493_ = ~new_n466_ & ~new_n468_;
  assign new_n494_ = ~new_n469_ & ~new_n493_;
  assign new_n495_ = new_n492_ & ~new_n494_;
  assign new_n496_ = new_n370_ & new_n495_;
  assign new_n497_ = ~new_n366_ & ~new_n370_;
  assign new_n498_ = ~new_n371_ & ~new_n497_;
  assign new_n499_ = ~new_n495_ & ~new_n498_;
  assign new_n500_ = ~new_n480_ & ~new_n499_;
  assign new_n501_ = ~new_n496_ & ~new_n500_;
  assign new_n502_ = ~new_n490_ & new_n501_;
  assign new_n503_ = new_n465_ & ~new_n474_;
  assign new_n504_ = ~new_n475_ & ~new_n503_;
  assign new_n505_ = new_n490_ & ~new_n501_;
  assign new_n506_ = new_n504_ & ~new_n505_;
  assign new_n507_ = ~new_n502_ & ~new_n506_;
  assign new_n508_ = ~new_n488_ & new_n507_;
  assign new_n509_ = ~new_n482_ & ~new_n487_;
  assign new_n510_ = ~new_n508_ & new_n509_;
  assign new_n511_ = ~new_n481_ & ~new_n510_;
  assign new_n512_ = ~new_n480_ & ~new_n511_;
  assign new_n513_ = ~new_n498_ & new_n511_;
  assign new_n514_ = ~new_n512_ & ~new_n513_;
  assign new_n515_ = ~new_n256_ & new_n269_;
  assign new_n516_ = ~new_n254_ & ~new_n269_;
  assign new_n517_ = ~new_n515_ & ~new_n516_;
  assign new_n518_ = new_n514_ & ~new_n517_;
  assign new_n519_ = ~new_n494_ & ~new_n511_;
  assign new_n520_ = ~new_n492_ & new_n511_;
  assign new_n521_ = ~new_n519_ & ~new_n520_;
  assign new_n522_ = ~new_n248_ & new_n269_;
  assign new_n523_ = ~new_n250_ & ~new_n269_;
  assign new_n524_ = ~new_n522_ & ~new_n523_;
  assign new_n525_ = ~new_n521_ & new_n524_;
  assign new_n526_ = ~new_n518_ & new_n525_;
  assign new_n527_ = new_n490_ & new_n511_;
  assign new_n528_ = new_n504_ & ~new_n511_;
  assign new_n529_ = ~new_n527_ & ~new_n528_;
  assign new_n530_ = new_n246_ & new_n269_;
  assign new_n531_ = new_n262_ & ~new_n269_;
  assign new_n532_ = ~new_n530_ & ~new_n531_;
  assign new_n533_ = new_n529_ & ~new_n532_;
  assign new_n534_ = ~new_n514_ & new_n517_;
  assign new_n535_ = ~new_n533_ & ~new_n534_;
  assign new_n536_ = ~new_n526_ & new_n535_;
  assign new_n537_ = new_n238_ & new_n241_;
  assign new_n538_ = new_n270_ & ~new_n537_;
  assign new_n539_ = new_n483_ & new_n485_;
  assign new_n540_ = new_n477_ & ~new_n539_;
  assign new_n541_ = ~new_n538_ & new_n540_;
  assign new_n542_ = ~new_n529_ & new_n532_;
  assign new_n543_ = ~new_n541_ & ~new_n542_;
  assign new_n544_ = ~new_n536_ & new_n543_;
  assign new_n545_ = ~new_n270_ & new_n477_;
  assign new_n546_ = new_n538_ & ~new_n540_;
  assign new_n547_ = ~new_n545_ & ~new_n546_;
  assign new_n548_ = ~new_n544_ & new_n547_;
  assign \o[1]  = new_n478_ | new_n548_;
  assign new_n550_ = ~new_n269_ & ~\o[1] ;
  assign new_n551_ = ~new_n511_ & \o[1] ;
  assign \o[0]  = new_n550_ | new_n551_;
endmodule


