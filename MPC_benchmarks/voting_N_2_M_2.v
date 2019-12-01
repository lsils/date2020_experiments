// Benchmark "voting_BMR_2_2" written by ABC on Tue Nov 26 14:00:41 2019

module voting_BMR_2_2 ( 
    \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] , \p_input[4] ,
    \p_input[5] , \p_input[6] , \p_input[7] ,
    \o[0] , \o[1]   );
  input  \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] ,
    \p_input[4] , \p_input[5] , \p_input[6] , \p_input[7] ;
  output \o[0] , \o[1] ;
  wire new_n11_, new_n12_, new_n13_, new_n14_, new_n15_, new_n16_, new_n17_,
    new_n18_, new_n19_, new_n20_, new_n21_, new_n22_, new_n23_, new_n24_,
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
    new_n95_, new_n96_, new_n97_, new_n98_, new_n99_, new_n100_, new_n101_,
    new_n102_, new_n103_, new_n104_, new_n105_, new_n106_, new_n107_,
    new_n108_, new_n109_, new_n110_, new_n112_, new_n113_;
  assign new_n11_ = \p_input[0]  & \p_input[1] ;
  assign new_n12_ = \p_input[6]  & \p_input[7] ;
  assign new_n13_ = \p_input[4]  & \p_input[5] ;
  assign new_n14_ = \p_input[2]  & \p_input[3] ;
  assign new_n15_ = ~new_n13_ & ~new_n14_;
  assign new_n16_ = new_n13_ & new_n14_;
  assign new_n17_ = ~new_n15_ & ~new_n16_;
  assign new_n18_ = new_n12_ & ~new_n17_;
  assign new_n19_ = ~new_n12_ & new_n17_;
  assign new_n20_ = ~new_n18_ & ~new_n19_;
  assign new_n21_ = new_n11_ & ~new_n20_;
  assign new_n22_ = ~new_n12_ & ~new_n16_;
  assign new_n23_ = ~new_n15_ & ~new_n22_;
  assign new_n24_ = new_n21_ & new_n23_;
  assign new_n25_ = ~new_n21_ & ~new_n23_;
  assign new_n26_ = ~new_n24_ & ~new_n25_;
  assign new_n27_ = ~\p_input[0]  & \p_input[1] ;
  assign new_n28_ = ~\p_input[6]  & \p_input[7] ;
  assign new_n29_ = ~\p_input[4]  & \p_input[5] ;
  assign new_n30_ = ~\p_input[2]  & \p_input[3] ;
  assign new_n31_ = ~new_n29_ & ~new_n30_;
  assign new_n32_ = new_n29_ & new_n30_;
  assign new_n33_ = ~new_n31_ & ~new_n32_;
  assign new_n34_ = new_n28_ & ~new_n33_;
  assign new_n35_ = ~new_n28_ & new_n33_;
  assign new_n36_ = ~new_n34_ & ~new_n35_;
  assign new_n37_ = new_n27_ & ~new_n36_;
  assign new_n38_ = ~new_n27_ & new_n36_;
  assign new_n39_ = ~new_n37_ & ~new_n38_;
  assign new_n40_ = ~new_n11_ & new_n20_;
  assign new_n41_ = ~new_n21_ & ~new_n40_;
  assign new_n42_ = new_n39_ & ~new_n41_;
  assign new_n43_ = ~new_n26_ & new_n42_;
  assign new_n44_ = ~new_n28_ & ~new_n32_;
  assign new_n45_ = ~new_n31_ & ~new_n44_;
  assign new_n46_ = ~new_n37_ & ~new_n45_;
  assign new_n47_ = new_n26_ & ~new_n42_;
  assign new_n48_ = ~new_n46_ & ~new_n47_;
  assign new_n49_ = ~new_n43_ & ~new_n48_;
  assign new_n50_ = \p_input[0]  & ~\p_input[1] ;
  assign new_n51_ = \p_input[6]  & ~\p_input[7] ;
  assign new_n52_ = \p_input[4]  & ~\p_input[5] ;
  assign new_n53_ = \p_input[2]  & ~\p_input[3] ;
  assign new_n54_ = ~new_n52_ & ~new_n53_;
  assign new_n55_ = new_n52_ & new_n53_;
  assign new_n56_ = ~new_n54_ & ~new_n55_;
  assign new_n57_ = new_n51_ & ~new_n56_;
  assign new_n58_ = ~new_n51_ & new_n56_;
  assign new_n59_ = ~new_n57_ & ~new_n58_;
  assign new_n60_ = new_n50_ & ~new_n59_;
  assign new_n61_ = ~new_n51_ & ~new_n55_;
  assign new_n62_ = ~new_n54_ & ~new_n61_;
  assign new_n63_ = new_n60_ & new_n62_;
  assign new_n64_ = ~\p_input[4]  & ~\p_input[5] ;
  assign new_n65_ = ~\p_input[2]  & ~\p_input[3] ;
  assign new_n66_ = ~new_n64_ & ~new_n65_;
  assign new_n67_ = ~\p_input[6]  & ~\p_input[7] ;
  assign new_n68_ = new_n64_ & new_n65_;
  assign new_n69_ = ~new_n66_ & ~new_n68_;
  assign new_n70_ = ~new_n67_ & new_n69_;
  assign new_n71_ = ~new_n66_ & ~new_n70_;
  assign new_n72_ = ~\p_input[0]  & ~\p_input[1] ;
  assign new_n73_ = new_n67_ & ~new_n69_;
  assign new_n74_ = ~new_n70_ & ~new_n73_;
  assign new_n75_ = new_n72_ & ~new_n74_;
  assign new_n76_ = new_n71_ & new_n75_;
  assign new_n77_ = ~new_n63_ & ~new_n76_;
  assign new_n78_ = new_n37_ & new_n45_;
  assign new_n79_ = ~new_n24_ & ~new_n78_;
  assign new_n80_ = new_n77_ & ~new_n79_;
  assign new_n81_ = ~new_n77_ & new_n79_;
  assign new_n82_ = ~new_n46_ & ~new_n78_;
  assign new_n83_ = ~new_n26_ & ~new_n82_;
  assign new_n84_ = ~new_n60_ & ~new_n62_;
  assign new_n85_ = ~new_n63_ & ~new_n84_;
  assign new_n86_ = ~new_n71_ & ~new_n75_;
  assign new_n87_ = ~new_n76_ & ~new_n86_;
  assign new_n88_ = ~new_n85_ & ~new_n87_;
  assign new_n89_ = new_n83_ & ~new_n88_;
  assign new_n90_ = ~new_n72_ & new_n74_;
  assign new_n91_ = ~new_n75_ & ~new_n90_;
  assign new_n92_ = new_n85_ & ~new_n87_;
  assign new_n93_ = ~new_n50_ & new_n59_;
  assign new_n94_ = ~new_n60_ & ~new_n93_;
  assign new_n95_ = new_n91_ & ~new_n94_;
  assign new_n96_ = ~new_n92_ & new_n95_;
  assign new_n97_ = new_n84_ & ~new_n86_;
  assign new_n98_ = ~new_n96_ & ~new_n97_;
  assign new_n99_ = ~new_n63_ & ~new_n98_;
  assign new_n100_ = ~new_n91_ & new_n99_;
  assign new_n101_ = ~new_n94_ & ~new_n99_;
  assign new_n102_ = new_n39_ & ~new_n49_;
  assign new_n103_ = new_n41_ & ~new_n48_;
  assign new_n104_ = ~new_n83_ & new_n88_;
  assign new_n105_ = ~new_n103_ & ~new_n104_;
  assign new_n106_ = ~new_n102_ & new_n105_;
  assign new_n107_ = ~new_n100_ & new_n106_;
  assign new_n108_ = ~new_n101_ & new_n107_;
  assign new_n109_ = ~new_n81_ & ~new_n89_;
  assign new_n110_ = ~new_n108_ & new_n109_;
  assign \o[1]  = new_n80_ | new_n110_;
  assign new_n112_ = ~new_n49_ & \o[1] ;
  assign new_n113_ = new_n99_ & ~\o[1] ;
  assign \o[0]  = ~new_n112_ & ~new_n113_;
endmodule


