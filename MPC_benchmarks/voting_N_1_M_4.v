// Benchmark "voting_BMR_1_4" written by ABC on Tue Nov 26 13:54:23 2019

module voting_BMR_1_4 ( 
    \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] , \p_input[4] ,
    \p_input[5] , \p_input[6] , \p_input[7] , \p_input[8] , \p_input[9] ,
    \p_input[10] , \p_input[11] , \p_input[12] , \p_input[13] ,
    \p_input[14] , \p_input[15] ,
    o  );
  input  \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] ,
    \p_input[4] , \p_input[5] , \p_input[6] , \p_input[7] , \p_input[8] ,
    \p_input[9] , \p_input[10] , \p_input[11] , \p_input[12] ,
    \p_input[13] , \p_input[14] , \p_input[15] ;
  output o;
  wire new_n18_, new_n19_, new_n20_, new_n21_, new_n22_, new_n23_, new_n24_,
    new_n25_, new_n26_, new_n27_, new_n28_, new_n29_, new_n30_, new_n31_,
    new_n32_, new_n33_, new_n34_, new_n35_, new_n36_, new_n37_, new_n38_,
    new_n39_, new_n40_, new_n41_, new_n42_, new_n43_, new_n44_, new_n45_,
    new_n46_, new_n47_, new_n48_, new_n49_, new_n50_, new_n51_, new_n52_,
    new_n53_, new_n54_, new_n55_, new_n56_, new_n57_, new_n58_, new_n59_,
    new_n60_, new_n61_, new_n62_, new_n63_, new_n64_, new_n65_, new_n66_,
    new_n67_, new_n68_, new_n69_, new_n70_, new_n71_, new_n72_, new_n73_,
    new_n74_, new_n75_, new_n76_, new_n77_, new_n78_, new_n79_, new_n80_,
    new_n81_, new_n82_, new_n83_, new_n84_, new_n85_, new_n86_, new_n87_,
    new_n88_, new_n89_, new_n90_, new_n91_, new_n92_, new_n93_, new_n94_,
    new_n95_, new_n96_, new_n97_, new_n98_;
  assign new_n18_ = \p_input[13]  & \p_input[14] ;
  assign new_n19_ = ~\p_input[13]  & ~\p_input[14] ;
  assign new_n20_ = ~new_n18_ & ~new_n19_;
  assign new_n21_ = \p_input[15]  & new_n20_;
  assign new_n22_ = ~new_n18_ & ~new_n21_;
  assign new_n23_ = ~\p_input[15]  & ~new_n20_;
  assign new_n24_ = ~new_n21_ & ~new_n23_;
  assign new_n25_ = \p_input[9]  & new_n24_;
  assign new_n26_ = ~\p_input[9]  & ~new_n24_;
  assign new_n27_ = ~\p_input[10]  & ~\p_input[11] ;
  assign new_n28_ = \p_input[10]  & \p_input[11] ;
  assign new_n29_ = ~new_n27_ & ~new_n28_;
  assign new_n30_ = \p_input[12]  & new_n29_;
  assign new_n31_ = ~\p_input[12]  & ~new_n29_;
  assign new_n32_ = ~new_n30_ & ~new_n31_;
  assign new_n33_ = ~new_n26_ & new_n32_;
  assign new_n34_ = ~new_n25_ & ~new_n33_;
  assign new_n35_ = ~new_n22_ & ~new_n34_;
  assign new_n36_ = ~new_n28_ & ~new_n30_;
  assign new_n37_ = new_n22_ & new_n34_;
  assign new_n38_ = ~new_n35_ & ~new_n37_;
  assign new_n39_ = ~new_n36_ & new_n38_;
  assign new_n40_ = ~new_n35_ & ~new_n39_;
  assign new_n41_ = new_n36_ & ~new_n38_;
  assign new_n42_ = ~new_n39_ & ~new_n41_;
  assign new_n43_ = ~new_n25_ & ~new_n26_;
  assign new_n44_ = new_n32_ & ~new_n43_;
  assign new_n45_ = ~new_n32_ & new_n43_;
  assign new_n46_ = ~new_n44_ & ~new_n45_;
  assign new_n47_ = ~\p_input[1]  & new_n46_;
  assign new_n48_ = \p_input[1]  & ~new_n46_;
  assign new_n49_ = ~\p_input[3]  & ~\p_input[4] ;
  assign new_n50_ = \p_input[3]  & \p_input[4] ;
  assign new_n51_ = ~new_n49_ & ~new_n50_;
  assign new_n52_ = \p_input[5]  & new_n51_;
  assign new_n53_ = ~\p_input[5]  & ~new_n51_;
  assign new_n54_ = ~new_n52_ & ~new_n53_;
  assign new_n55_ = ~\p_input[6]  & ~\p_input[7] ;
  assign new_n56_ = \p_input[6]  & \p_input[7] ;
  assign new_n57_ = ~new_n55_ & ~new_n56_;
  assign new_n58_ = \p_input[8]  & new_n57_;
  assign new_n59_ = ~\p_input[8]  & ~new_n57_;
  assign new_n60_ = ~new_n58_ & ~new_n59_;
  assign new_n61_ = \p_input[2]  & new_n60_;
  assign new_n62_ = ~\p_input[2]  & ~new_n60_;
  assign new_n63_ = ~new_n61_ & ~new_n62_;
  assign new_n64_ = new_n54_ & new_n63_;
  assign new_n65_ = ~new_n54_ & ~new_n63_;
  assign new_n66_ = ~new_n64_ & ~new_n65_;
  assign new_n67_ = ~new_n48_ & ~new_n66_;
  assign new_n68_ = ~new_n47_ & ~new_n67_;
  assign new_n69_ = ~new_n42_ & ~new_n68_;
  assign new_n70_ = new_n42_ & new_n68_;
  assign new_n71_ = ~new_n50_ & ~new_n52_;
  assign new_n72_ = ~new_n56_ & ~new_n58_;
  assign new_n73_ = ~new_n61_ & ~new_n64_;
  assign new_n74_ = new_n72_ & new_n73_;
  assign new_n75_ = ~new_n72_ & ~new_n73_;
  assign new_n76_ = ~new_n74_ & ~new_n75_;
  assign new_n77_ = ~new_n71_ & new_n76_;
  assign new_n78_ = new_n71_ & ~new_n76_;
  assign new_n79_ = ~new_n77_ & ~new_n78_;
  assign new_n80_ = ~new_n70_ & ~new_n79_;
  assign new_n81_ = ~new_n69_ & ~new_n80_;
  assign new_n82_ = new_n40_ & ~new_n81_;
  assign new_n83_ = ~new_n75_ & ~new_n77_;
  assign new_n84_ = new_n82_ & new_n83_;
  assign new_n85_ = ~new_n47_ & ~new_n48_;
  assign new_n86_ = new_n66_ & new_n85_;
  assign new_n87_ = ~new_n66_ & ~new_n85_;
  assign new_n88_ = ~new_n69_ & ~new_n70_;
  assign new_n89_ = ~new_n79_ & new_n88_;
  assign new_n90_ = new_n79_ & ~new_n88_;
  assign new_n91_ = ~new_n89_ & ~new_n90_;
  assign new_n92_ = \p_input[0]  & ~new_n86_;
  assign new_n93_ = ~new_n87_ & new_n92_;
  assign new_n94_ = ~new_n91_ & new_n93_;
  assign new_n95_ = ~new_n84_ & new_n94_;
  assign new_n96_ = ~new_n40_ & new_n81_;
  assign new_n97_ = new_n83_ & ~new_n96_;
  assign new_n98_ = ~new_n82_ & ~new_n97_;
  assign o = new_n95_ | new_n98_;
endmodule


