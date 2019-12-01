// Benchmark "auction_BMR_2_16" written by ABC on Tue Nov 26 13:54:47 2019

module auction_BMR_2_16 ( 
    \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] , \p_input[4] ,
    \p_input[5] , \p_input[6] , \p_input[7] , \p_input[8] , \p_input[9] ,
    \p_input[10] , \p_input[11] , \p_input[12] , \p_input[13] ,
    \p_input[14] , \p_input[15] , \p_input[16] , \p_input[17] ,
    \p_input[18] , \p_input[19] , \p_input[20] , \p_input[21] ,
    \p_input[22] , \p_input[23] , \p_input[24] , \p_input[25] ,
    \p_input[26] , \p_input[27] , \p_input[28] , \p_input[29] ,
    \p_input[30] , \p_input[31] , \p_input[32] , \p_input[33] ,
    \p_input[34] , \p_input[35] , \p_input[36] , \p_input[37] ,
    \p_input[38] , \p_input[39] , \p_input[40] , \p_input[41] ,
    \p_input[42] , \p_input[43] , \p_input[44] , \p_input[45] ,
    \p_input[46] , \p_input[47] , \p_input[48] , \p_input[49] ,
    \p_input[50] , \p_input[51] , \p_input[52] , \p_input[53] ,
    \p_input[54] , \p_input[55] , \p_input[56] , \p_input[57] ,
    \p_input[58] , \p_input[59] , \p_input[60] , \p_input[61] ,
    \p_input[62] , \p_input[63] ,
    \o[0] , \o[1] , \o[2] , \o[3] , \o[4] , \o[5] , \o[6] , \o[7] , \o[8] ,
    \o[9] , \o[10] , \o[11] , \o[12] , \o[13] , \o[14] , \o[15] , \o[16] ,
    \o[17]   );
  input  \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] ,
    \p_input[4] , \p_input[5] , \p_input[6] , \p_input[7] , \p_input[8] ,
    \p_input[9] , \p_input[10] , \p_input[11] , \p_input[12] ,
    \p_input[13] , \p_input[14] , \p_input[15] , \p_input[16] ,
    \p_input[17] , \p_input[18] , \p_input[19] , \p_input[20] ,
    \p_input[21] , \p_input[22] , \p_input[23] , \p_input[24] ,
    \p_input[25] , \p_input[26] , \p_input[27] , \p_input[28] ,
    \p_input[29] , \p_input[30] , \p_input[31] , \p_input[32] ,
    \p_input[33] , \p_input[34] , \p_input[35] , \p_input[36] ,
    \p_input[37] , \p_input[38] , \p_input[39] , \p_input[40] ,
    \p_input[41] , \p_input[42] , \p_input[43] , \p_input[44] ,
    \p_input[45] , \p_input[46] , \p_input[47] , \p_input[48] ,
    \p_input[49] , \p_input[50] , \p_input[51] , \p_input[52] ,
    \p_input[53] , \p_input[54] , \p_input[55] , \p_input[56] ,
    \p_input[57] , \p_input[58] , \p_input[59] , \p_input[60] ,
    \p_input[61] , \p_input[62] , \p_input[63] ;
  output \o[0] , \o[1] , \o[2] , \o[3] , \o[4] , \o[5] , \o[6] , \o[7] ,
    \o[8] , \o[9] , \o[10] , \o[11] , \o[12] , \o[13] , \o[14] , \o[15] ,
    \o[16] , \o[17] ;
  wire new_n83_, new_n84_, new_n85_, new_n86_, new_n87_, new_n88_, new_n89_,
    new_n90_, new_n91_, new_n92_, new_n93_, new_n94_, new_n95_, new_n96_,
    new_n97_, new_n98_, new_n99_, new_n100_, new_n101_, new_n102_,
    new_n103_, new_n104_, new_n105_, new_n106_, new_n107_, new_n108_,
    new_n109_, new_n110_, new_n111_, new_n112_, new_n113_, new_n114_,
    new_n115_, new_n116_, new_n117_, new_n118_, new_n119_, new_n120_,
    new_n121_, new_n122_, new_n123_, new_n124_, new_n125_, new_n126_,
    new_n127_, new_n128_, new_n129_, new_n130_, new_n131_, new_n132_,
    new_n133_, new_n134_, new_n135_, new_n136_, new_n137_, new_n138_,
    new_n139_, new_n140_, new_n141_, new_n142_, new_n143_, new_n144_,
    new_n145_, new_n146_, new_n147_, new_n148_, new_n149_, new_n150_,
    new_n151_, new_n152_, new_n153_, new_n154_, new_n155_, new_n156_,
    new_n157_, new_n158_, new_n159_, new_n160_, new_n161_, new_n162_,
    new_n163_, new_n164_, new_n165_, new_n166_, new_n167_, new_n168_,
    new_n169_, new_n170_, new_n171_, new_n172_, new_n173_, new_n174_,
    new_n175_, new_n176_, new_n177_, new_n178_, new_n179_, new_n180_,
    new_n181_, new_n182_, new_n183_, new_n184_, new_n185_, new_n186_,
    new_n187_, new_n188_, new_n189_, new_n190_, new_n191_, new_n192_,
    new_n193_, new_n194_, new_n195_, new_n196_, new_n197_, new_n198_,
    new_n199_, new_n200_, new_n201_, new_n202_, new_n203_, new_n204_,
    new_n205_, new_n206_, new_n207_, new_n208_, new_n209_, new_n210_,
    new_n211_, new_n212_, new_n213_, new_n214_, new_n215_, new_n216_,
    new_n217_, new_n218_, new_n219_, new_n220_, new_n221_, new_n222_,
    new_n223_, new_n224_, new_n225_, new_n226_, new_n227_, new_n228_,
    new_n229_, new_n230_, new_n231_, new_n232_, new_n233_, new_n234_,
    new_n235_, new_n236_, new_n237_, new_n238_, new_n239_, new_n240_,
    new_n241_, new_n242_, new_n243_, new_n244_, new_n245_, new_n246_,
    new_n247_, new_n248_, new_n249_, new_n250_, new_n251_, new_n252_,
    new_n253_, new_n254_, new_n255_, new_n256_, new_n257_, new_n258_,
    new_n259_, new_n260_, new_n261_, new_n262_, new_n263_, new_n264_,
    new_n265_, new_n266_, new_n267_, new_n268_, new_n269_, new_n270_,
    new_n271_, new_n272_, new_n273_, new_n274_, new_n275_, new_n276_,
    new_n277_, new_n278_, new_n279_, new_n280_, new_n281_, new_n282_,
    new_n283_, new_n284_, new_n285_, new_n286_, new_n287_, new_n288_,
    new_n289_, new_n290_, new_n291_, new_n292_, new_n293_, new_n294_,
    new_n295_, new_n296_, new_n297_, new_n298_, new_n299_, new_n300_,
    new_n301_, new_n302_, new_n303_, new_n304_, new_n305_, new_n306_,
    new_n307_, new_n308_, new_n309_, new_n310_, new_n311_, new_n312_,
    new_n313_, new_n314_, new_n315_, new_n316_, new_n317_, new_n318_,
    new_n319_, new_n320_, new_n321_, new_n322_, new_n323_, new_n324_,
    new_n325_, new_n326_, new_n327_, new_n328_, new_n329_, new_n330_,
    new_n331_, new_n332_, new_n333_, new_n334_, new_n335_, new_n336_,
    new_n337_, new_n338_, new_n339_, new_n340_, new_n341_, new_n342_,
    new_n343_, new_n344_, new_n345_, new_n346_, new_n347_, new_n348_,
    new_n349_, new_n350_, new_n351_, new_n352_, new_n353_, new_n354_,
    new_n355_, new_n356_, new_n358_, new_n359_, new_n361_, new_n362_,
    new_n364_, new_n365_, new_n367_, new_n368_, new_n370_, new_n371_,
    new_n373_, new_n374_, new_n376_, new_n377_, new_n379_, new_n380_,
    new_n382_, new_n383_, new_n385_, new_n386_, new_n388_, new_n389_,
    new_n391_, new_n392_, new_n394_, new_n395_, new_n397_, new_n398_,
    new_n400_, new_n401_, new_n403_, new_n404_;
  assign new_n83_ = ~\p_input[47]  & \p_input[63] ;
  assign new_n84_ = \p_input[47]  & ~\p_input[63] ;
  assign new_n85_ = ~\p_input[46]  & \p_input[62] ;
  assign new_n86_ = \p_input[46]  & ~\p_input[62] ;
  assign new_n87_ = ~\p_input[45]  & \p_input[61] ;
  assign new_n88_ = \p_input[45]  & ~\p_input[61] ;
  assign new_n89_ = ~\p_input[44]  & \p_input[60] ;
  assign new_n90_ = \p_input[44]  & ~\p_input[60] ;
  assign new_n91_ = ~\p_input[43]  & \p_input[59] ;
  assign new_n92_ = \p_input[43]  & ~\p_input[59] ;
  assign new_n93_ = ~\p_input[42]  & \p_input[58] ;
  assign new_n94_ = \p_input[42]  & ~\p_input[58] ;
  assign new_n95_ = ~\p_input[41]  & \p_input[57] ;
  assign new_n96_ = \p_input[41]  & ~\p_input[57] ;
  assign new_n97_ = ~\p_input[40]  & \p_input[56] ;
  assign new_n98_ = \p_input[40]  & ~\p_input[56] ;
  assign new_n99_ = ~\p_input[39]  & \p_input[55] ;
  assign new_n100_ = \p_input[39]  & ~\p_input[55] ;
  assign new_n101_ = ~\p_input[38]  & \p_input[54] ;
  assign new_n102_ = \p_input[38]  & ~\p_input[54] ;
  assign new_n103_ = ~\p_input[37]  & \p_input[53] ;
  assign new_n104_ = \p_input[37]  & ~\p_input[53] ;
  assign new_n105_ = ~\p_input[36]  & \p_input[52] ;
  assign new_n106_ = \p_input[36]  & ~\p_input[52] ;
  assign new_n107_ = ~\p_input[35]  & \p_input[51] ;
  assign new_n108_ = \p_input[35]  & ~\p_input[51] ;
  assign new_n109_ = ~\p_input[34]  & \p_input[50] ;
  assign new_n110_ = \p_input[34]  & ~\p_input[50] ;
  assign new_n111_ = ~\p_input[33]  & \p_input[49] ;
  assign new_n112_ = \p_input[33]  & ~\p_input[49] ;
  assign new_n113_ = \p_input[32]  & ~\p_input[48] ;
  assign new_n114_ = ~new_n112_ & ~new_n113_;
  assign new_n115_ = ~new_n111_ & ~new_n114_;
  assign new_n116_ = ~new_n110_ & ~new_n115_;
  assign new_n117_ = ~new_n109_ & ~new_n116_;
  assign new_n118_ = ~new_n108_ & ~new_n117_;
  assign new_n119_ = ~new_n107_ & ~new_n118_;
  assign new_n120_ = ~new_n106_ & ~new_n119_;
  assign new_n121_ = ~new_n105_ & ~new_n120_;
  assign new_n122_ = ~new_n104_ & ~new_n121_;
  assign new_n123_ = ~new_n103_ & ~new_n122_;
  assign new_n124_ = ~new_n102_ & ~new_n123_;
  assign new_n125_ = ~new_n101_ & ~new_n124_;
  assign new_n126_ = ~new_n100_ & ~new_n125_;
  assign new_n127_ = ~new_n99_ & ~new_n126_;
  assign new_n128_ = ~new_n98_ & ~new_n127_;
  assign new_n129_ = ~new_n97_ & ~new_n128_;
  assign new_n130_ = ~new_n96_ & ~new_n129_;
  assign new_n131_ = ~new_n95_ & ~new_n130_;
  assign new_n132_ = ~new_n94_ & ~new_n131_;
  assign new_n133_ = ~new_n93_ & ~new_n132_;
  assign new_n134_ = ~new_n92_ & ~new_n133_;
  assign new_n135_ = ~new_n91_ & ~new_n134_;
  assign new_n136_ = ~new_n90_ & ~new_n135_;
  assign new_n137_ = ~new_n89_ & ~new_n136_;
  assign new_n138_ = ~new_n88_ & ~new_n137_;
  assign new_n139_ = ~new_n87_ & ~new_n138_;
  assign new_n140_ = ~new_n86_ & ~new_n139_;
  assign new_n141_ = ~new_n85_ & ~new_n140_;
  assign new_n142_ = ~new_n84_ & ~new_n141_;
  assign new_n143_ = ~new_n83_ & ~new_n142_;
  assign new_n144_ = ~\p_input[47]  & ~\p_input[63] ;
  assign new_n145_ = ~\p_input[15]  & ~\p_input[31] ;
  assign new_n146_ = ~new_n144_ & new_n145_;
  assign new_n147_ = new_n144_ & ~new_n145_;
  assign new_n148_ = \p_input[62]  & ~new_n143_;
  assign new_n149_ = \p_input[46]  & new_n143_;
  assign new_n150_ = ~new_n148_ & ~new_n149_;
  assign new_n151_ = ~\p_input[15]  & \p_input[31] ;
  assign new_n152_ = \p_input[15]  & ~\p_input[31] ;
  assign new_n153_ = ~\p_input[14]  & \p_input[30] ;
  assign new_n154_ = \p_input[14]  & ~\p_input[30] ;
  assign new_n155_ = ~\p_input[13]  & \p_input[29] ;
  assign new_n156_ = \p_input[13]  & ~\p_input[29] ;
  assign new_n157_ = ~\p_input[12]  & \p_input[28] ;
  assign new_n158_ = \p_input[12]  & ~\p_input[28] ;
  assign new_n159_ = ~\p_input[11]  & \p_input[27] ;
  assign new_n160_ = \p_input[11]  & ~\p_input[27] ;
  assign new_n161_ = ~\p_input[10]  & \p_input[26] ;
  assign new_n162_ = \p_input[10]  & ~\p_input[26] ;
  assign new_n163_ = ~\p_input[9]  & \p_input[25] ;
  assign new_n164_ = \p_input[9]  & ~\p_input[25] ;
  assign new_n165_ = ~\p_input[8]  & \p_input[24] ;
  assign new_n166_ = \p_input[8]  & ~\p_input[24] ;
  assign new_n167_ = ~\p_input[7]  & \p_input[23] ;
  assign new_n168_ = \p_input[7]  & ~\p_input[23] ;
  assign new_n169_ = ~\p_input[6]  & \p_input[22] ;
  assign new_n170_ = \p_input[6]  & ~\p_input[22] ;
  assign new_n171_ = ~\p_input[5]  & \p_input[21] ;
  assign new_n172_ = \p_input[5]  & ~\p_input[21] ;
  assign new_n173_ = ~\p_input[4]  & \p_input[20] ;
  assign new_n174_ = \p_input[4]  & ~\p_input[20] ;
  assign new_n175_ = ~\p_input[3]  & \p_input[19] ;
  assign new_n176_ = \p_input[3]  & ~\p_input[19] ;
  assign new_n177_ = ~\p_input[2]  & \p_input[18] ;
  assign new_n178_ = \p_input[2]  & ~\p_input[18] ;
  assign new_n179_ = ~\p_input[1]  & \p_input[17] ;
  assign new_n180_ = \p_input[1]  & ~\p_input[17] ;
  assign new_n181_ = \p_input[0]  & ~\p_input[16] ;
  assign new_n182_ = ~new_n180_ & ~new_n181_;
  assign new_n183_ = ~new_n179_ & ~new_n182_;
  assign new_n184_ = ~new_n178_ & ~new_n183_;
  assign new_n185_ = ~new_n177_ & ~new_n184_;
  assign new_n186_ = ~new_n176_ & ~new_n185_;
  assign new_n187_ = ~new_n175_ & ~new_n186_;
  assign new_n188_ = ~new_n174_ & ~new_n187_;
  assign new_n189_ = ~new_n173_ & ~new_n188_;
  assign new_n190_ = ~new_n172_ & ~new_n189_;
  assign new_n191_ = ~new_n171_ & ~new_n190_;
  assign new_n192_ = ~new_n170_ & ~new_n191_;
  assign new_n193_ = ~new_n169_ & ~new_n192_;
  assign new_n194_ = ~new_n168_ & ~new_n193_;
  assign new_n195_ = ~new_n167_ & ~new_n194_;
  assign new_n196_ = ~new_n166_ & ~new_n195_;
  assign new_n197_ = ~new_n165_ & ~new_n196_;
  assign new_n198_ = ~new_n164_ & ~new_n197_;
  assign new_n199_ = ~new_n163_ & ~new_n198_;
  assign new_n200_ = ~new_n162_ & ~new_n199_;
  assign new_n201_ = ~new_n161_ & ~new_n200_;
  assign new_n202_ = ~new_n160_ & ~new_n201_;
  assign new_n203_ = ~new_n159_ & ~new_n202_;
  assign new_n204_ = ~new_n158_ & ~new_n203_;
  assign new_n205_ = ~new_n157_ & ~new_n204_;
  assign new_n206_ = ~new_n156_ & ~new_n205_;
  assign new_n207_ = ~new_n155_ & ~new_n206_;
  assign new_n208_ = ~new_n154_ & ~new_n207_;
  assign new_n209_ = ~new_n153_ & ~new_n208_;
  assign new_n210_ = ~new_n152_ & ~new_n209_;
  assign new_n211_ = ~new_n151_ & ~new_n210_;
  assign new_n212_ = \p_input[30]  & ~new_n211_;
  assign new_n213_ = \p_input[14]  & new_n211_;
  assign new_n214_ = ~new_n212_ & ~new_n213_;
  assign new_n215_ = ~new_n150_ & new_n214_;
  assign new_n216_ = \p_input[49]  & ~new_n143_;
  assign new_n217_ = \p_input[33]  & new_n143_;
  assign new_n218_ = ~new_n216_ & ~new_n217_;
  assign new_n219_ = \p_input[17]  & ~new_n211_;
  assign new_n220_ = \p_input[1]  & new_n211_;
  assign new_n221_ = ~new_n219_ & ~new_n220_;
  assign new_n222_ = ~new_n218_ & new_n221_;
  assign new_n223_ = \p_input[48]  & ~new_n143_;
  assign new_n224_ = \p_input[32]  & new_n143_;
  assign new_n225_ = ~new_n223_ & ~new_n224_;
  assign new_n226_ = \p_input[16]  & ~new_n211_;
  assign new_n227_ = \p_input[0]  & new_n211_;
  assign new_n228_ = ~new_n226_ & ~new_n227_;
  assign new_n229_ = new_n225_ & ~new_n228_;
  assign new_n230_ = ~new_n222_ & new_n229_;
  assign new_n231_ = \p_input[50]  & ~new_n143_;
  assign new_n232_ = \p_input[34]  & new_n143_;
  assign new_n233_ = ~new_n231_ & ~new_n232_;
  assign new_n234_ = \p_input[18]  & ~new_n211_;
  assign new_n235_ = \p_input[2]  & new_n211_;
  assign new_n236_ = ~new_n234_ & ~new_n235_;
  assign new_n237_ = new_n233_ & ~new_n236_;
  assign new_n238_ = new_n218_ & ~new_n221_;
  assign new_n239_ = ~new_n237_ & ~new_n238_;
  assign new_n240_ = ~new_n230_ & new_n239_;
  assign new_n241_ = \p_input[51]  & ~new_n143_;
  assign new_n242_ = \p_input[35]  & new_n143_;
  assign new_n243_ = ~new_n241_ & ~new_n242_;
  assign new_n244_ = \p_input[19]  & ~new_n211_;
  assign new_n245_ = \p_input[3]  & new_n211_;
  assign new_n246_ = ~new_n244_ & ~new_n245_;
  assign new_n247_ = ~new_n243_ & new_n246_;
  assign new_n248_ = ~new_n233_ & new_n236_;
  assign new_n249_ = ~new_n247_ & ~new_n248_;
  assign new_n250_ = ~new_n240_ & new_n249_;
  assign new_n251_ = \p_input[52]  & ~new_n143_;
  assign new_n252_ = \p_input[36]  & new_n143_;
  assign new_n253_ = ~new_n251_ & ~new_n252_;
  assign new_n254_ = \p_input[20]  & ~new_n211_;
  assign new_n255_ = \p_input[4]  & new_n211_;
  assign new_n256_ = ~new_n254_ & ~new_n255_;
  assign new_n257_ = new_n253_ & ~new_n256_;
  assign new_n258_ = new_n243_ & ~new_n246_;
  assign new_n259_ = ~new_n257_ & ~new_n258_;
  assign new_n260_ = ~new_n250_ & new_n259_;
  assign new_n261_ = ~new_n253_ & new_n256_;
  assign new_n262_ = \p_input[53]  & ~new_n143_;
  assign new_n263_ = \p_input[37]  & new_n143_;
  assign new_n264_ = ~new_n262_ & ~new_n263_;
  assign new_n265_ = \p_input[21]  & ~new_n211_;
  assign new_n266_ = \p_input[5]  & new_n211_;
  assign new_n267_ = ~new_n265_ & ~new_n266_;
  assign new_n268_ = ~new_n264_ & new_n267_;
  assign new_n269_ = ~new_n261_ & ~new_n268_;
  assign new_n270_ = ~new_n260_ & new_n269_;
  assign new_n271_ = \p_input[54]  & ~new_n143_;
  assign new_n272_ = \p_input[38]  & new_n143_;
  assign new_n273_ = ~new_n271_ & ~new_n272_;
  assign new_n274_ = \p_input[22]  & ~new_n211_;
  assign new_n275_ = \p_input[6]  & new_n211_;
  assign new_n276_ = ~new_n274_ & ~new_n275_;
  assign new_n277_ = new_n273_ & ~new_n276_;
  assign new_n278_ = new_n264_ & ~new_n267_;
  assign new_n279_ = ~new_n277_ & ~new_n278_;
  assign new_n280_ = ~new_n270_ & new_n279_;
  assign new_n281_ = \p_input[23]  & ~new_n211_;
  assign new_n282_ = \p_input[7]  & new_n211_;
  assign new_n283_ = ~new_n281_ & ~new_n282_;
  assign new_n284_ = \p_input[55]  & ~new_n143_;
  assign new_n285_ = \p_input[39]  & new_n143_;
  assign new_n286_ = ~new_n284_ & ~new_n285_;
  assign new_n287_ = new_n283_ & ~new_n286_;
  assign new_n288_ = ~new_n273_ & new_n276_;
  assign new_n289_ = ~new_n287_ & ~new_n288_;
  assign new_n290_ = ~new_n280_ & new_n289_;
  assign new_n291_ = ~new_n283_ & new_n286_;
  assign new_n292_ = \p_input[56]  & ~new_n143_;
  assign new_n293_ = \p_input[40]  & new_n143_;
  assign new_n294_ = ~new_n292_ & ~new_n293_;
  assign new_n295_ = \p_input[24]  & ~new_n211_;
  assign new_n296_ = \p_input[8]  & new_n211_;
  assign new_n297_ = ~new_n295_ & ~new_n296_;
  assign new_n298_ = new_n294_ & ~new_n297_;
  assign new_n299_ = ~new_n291_ & ~new_n298_;
  assign new_n300_ = ~new_n290_ & new_n299_;
  assign new_n301_ = ~new_n294_ & new_n297_;
  assign new_n302_ = \p_input[57]  & ~new_n143_;
  assign new_n303_ = \p_input[41]  & new_n143_;
  assign new_n304_ = ~new_n302_ & ~new_n303_;
  assign new_n305_ = \p_input[25]  & ~new_n211_;
  assign new_n306_ = \p_input[9]  & new_n211_;
  assign new_n307_ = ~new_n305_ & ~new_n306_;
  assign new_n308_ = ~new_n304_ & new_n307_;
  assign new_n309_ = ~new_n301_ & ~new_n308_;
  assign new_n310_ = ~new_n300_ & new_n309_;
  assign new_n311_ = new_n304_ & ~new_n307_;
  assign new_n312_ = \p_input[26]  & ~new_n211_;
  assign new_n313_ = \p_input[10]  & new_n211_;
  assign new_n314_ = ~new_n312_ & ~new_n313_;
  assign new_n315_ = \p_input[58]  & ~new_n143_;
  assign new_n316_ = \p_input[42]  & new_n143_;
  assign new_n317_ = ~new_n315_ & ~new_n316_;
  assign new_n318_ = ~new_n314_ & new_n317_;
  assign new_n319_ = ~new_n311_ & ~new_n318_;
  assign new_n320_ = ~new_n310_ & new_n319_;
  assign new_n321_ = \p_input[27]  & ~new_n211_;
  assign new_n322_ = \p_input[11]  & new_n211_;
  assign new_n323_ = ~new_n321_ & ~new_n322_;
  assign new_n324_ = \p_input[59]  & ~new_n143_;
  assign new_n325_ = \p_input[43]  & new_n143_;
  assign new_n326_ = ~new_n324_ & ~new_n325_;
  assign new_n327_ = new_n323_ & ~new_n326_;
  assign new_n328_ = new_n314_ & ~new_n317_;
  assign new_n329_ = ~new_n327_ & ~new_n328_;
  assign new_n330_ = ~new_n320_ & new_n329_;
  assign new_n331_ = \p_input[60]  & ~new_n143_;
  assign new_n332_ = \p_input[44]  & new_n143_;
  assign new_n333_ = ~new_n331_ & ~new_n332_;
  assign new_n334_ = \p_input[28]  & ~new_n211_;
  assign new_n335_ = \p_input[12]  & new_n211_;
  assign new_n336_ = ~new_n334_ & ~new_n335_;
  assign new_n337_ = new_n333_ & ~new_n336_;
  assign new_n338_ = ~new_n323_ & new_n326_;
  assign new_n339_ = ~new_n337_ & ~new_n338_;
  assign new_n340_ = ~new_n330_ & new_n339_;
  assign new_n341_ = ~new_n333_ & new_n336_;
  assign new_n342_ = \p_input[61]  & ~new_n143_;
  assign new_n343_ = \p_input[45]  & new_n143_;
  assign new_n344_ = ~new_n342_ & ~new_n343_;
  assign new_n345_ = \p_input[29]  & ~new_n211_;
  assign new_n346_ = \p_input[13]  & new_n211_;
  assign new_n347_ = ~new_n345_ & ~new_n346_;
  assign new_n348_ = ~new_n344_ & new_n347_;
  assign new_n349_ = ~new_n341_ & ~new_n348_;
  assign new_n350_ = ~new_n340_ & new_n349_;
  assign new_n351_ = new_n150_ & ~new_n214_;
  assign new_n352_ = new_n344_ & ~new_n347_;
  assign new_n353_ = ~new_n351_ & ~new_n352_;
  assign new_n354_ = ~new_n350_ & new_n353_;
  assign new_n355_ = ~new_n215_ & ~new_n354_;
  assign new_n356_ = ~new_n147_ & ~new_n355_;
  assign \o[1]  = new_n146_ | new_n356_;
  assign new_n358_ = ~new_n143_ & \o[1] ;
  assign new_n359_ = ~new_n211_ & ~\o[1] ;
  assign \o[0]  = new_n358_ | new_n359_;
  assign new_n361_ = ~new_n228_ & ~\o[1] ;
  assign new_n362_ = ~new_n225_ & \o[1] ;
  assign \o[2]  = new_n361_ | new_n362_;
  assign new_n364_ = ~new_n221_ & ~\o[1] ;
  assign new_n365_ = ~new_n218_ & \o[1] ;
  assign \o[3]  = new_n364_ | new_n365_;
  assign new_n367_ = ~new_n236_ & ~\o[1] ;
  assign new_n368_ = ~new_n233_ & \o[1] ;
  assign \o[4]  = new_n367_ | new_n368_;
  assign new_n370_ = ~new_n246_ & ~\o[1] ;
  assign new_n371_ = ~new_n243_ & \o[1] ;
  assign \o[5]  = new_n370_ | new_n371_;
  assign new_n373_ = ~new_n256_ & ~\o[1] ;
  assign new_n374_ = ~new_n253_ & \o[1] ;
  assign \o[6]  = new_n373_ | new_n374_;
  assign new_n376_ = ~new_n267_ & ~\o[1] ;
  assign new_n377_ = ~new_n264_ & \o[1] ;
  assign \o[7]  = new_n376_ | new_n377_;
  assign new_n379_ = ~new_n276_ & ~\o[1] ;
  assign new_n380_ = ~new_n273_ & \o[1] ;
  assign \o[8]  = new_n379_ | new_n380_;
  assign new_n382_ = ~new_n283_ & ~\o[1] ;
  assign new_n383_ = ~new_n286_ & \o[1] ;
  assign \o[9]  = new_n382_ | new_n383_;
  assign new_n385_ = ~new_n297_ & ~\o[1] ;
  assign new_n386_ = ~new_n294_ & \o[1] ;
  assign \o[10]  = new_n385_ | new_n386_;
  assign new_n388_ = ~new_n307_ & ~\o[1] ;
  assign new_n389_ = ~new_n304_ & \o[1] ;
  assign \o[11]  = new_n388_ | new_n389_;
  assign new_n391_ = ~new_n314_ & ~\o[1] ;
  assign new_n392_ = ~new_n317_ & \o[1] ;
  assign \o[12]  = new_n391_ | new_n392_;
  assign new_n394_ = ~new_n323_ & ~\o[1] ;
  assign new_n395_ = ~new_n326_ & \o[1] ;
  assign \o[13]  = new_n394_ | new_n395_;
  assign new_n397_ = ~new_n336_ & ~\o[1] ;
  assign new_n398_ = ~new_n333_ & \o[1] ;
  assign \o[14]  = new_n397_ | new_n398_;
  assign new_n400_ = ~new_n347_ & ~\o[1] ;
  assign new_n401_ = ~new_n344_ & \o[1] ;
  assign \o[15]  = new_n400_ | new_n401_;
  assign new_n403_ = ~new_n214_ & ~\o[1] ;
  assign new_n404_ = ~new_n150_ & \o[1] ;
  assign \o[16]  = new_n403_ | new_n404_;
  assign \o[17]  = ~new_n144_ | ~new_n145_;
endmodule


