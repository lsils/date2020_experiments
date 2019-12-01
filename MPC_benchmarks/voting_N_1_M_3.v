// Benchmark "voting_BMR_1_3" written by ABC on Tue Nov 26 13:54:12 2019

module voting_BMR_1_3 ( 
    \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] , \p_input[4] ,
    \p_input[5] , \p_input[6] , \p_input[7] ,
    o  );
  input  \p_input[0] , \p_input[1] , \p_input[2] , \p_input[3] ,
    \p_input[4] , \p_input[5] , \p_input[6] , \p_input[7] ;
  output o;
  wire new_n10_, new_n11_, new_n12_, new_n13_, new_n14_, new_n15_, new_n16_,
    new_n17_, new_n18_, new_n19_, new_n20_, new_n21_, new_n22_, new_n23_,
    new_n24_, new_n25_, new_n26_, new_n27_, new_n28_, new_n29_, new_n30_,
    new_n31_, new_n32_, new_n33_, new_n34_, new_n35_, new_n36_, new_n37_,
    new_n38_;
  assign new_n10_ = \p_input[2]  & \p_input[3] ;
  assign new_n11_ = ~\p_input[2]  & ~\p_input[3] ;
  assign new_n12_ = ~new_n10_ & ~new_n11_;
  assign new_n13_ = \p_input[4]  & new_n12_;
  assign new_n14_ = ~new_n10_ & ~new_n13_;
  assign new_n15_ = \p_input[5]  & \p_input[6] ;
  assign new_n16_ = ~\p_input[5]  & ~\p_input[6] ;
  assign new_n17_ = ~new_n15_ & ~new_n16_;
  assign new_n18_ = \p_input[7]  & new_n17_;
  assign new_n19_ = ~new_n15_ & ~new_n18_;
  assign new_n20_ = ~\p_input[7]  & ~new_n17_;
  assign new_n21_ = ~new_n18_ & ~new_n20_;
  assign new_n22_ = ~\p_input[1]  & ~new_n21_;
  assign new_n23_ = \p_input[1]  & new_n21_;
  assign new_n24_ = ~\p_input[4]  & ~new_n12_;
  assign new_n25_ = ~new_n13_ & ~new_n24_;
  assign new_n26_ = ~new_n23_ & ~new_n25_;
  assign new_n27_ = ~new_n22_ & ~new_n26_;
  assign new_n28_ = new_n19_ & ~new_n27_;
  assign new_n29_ = new_n14_ & new_n28_;
  assign new_n30_ = ~new_n22_ & ~new_n23_;
  assign new_n31_ = ~new_n25_ & new_n30_;
  assign new_n32_ = new_n25_ & ~new_n30_;
  assign new_n33_ = ~new_n31_ & ~new_n32_;
  assign new_n34_ = \p_input[0]  & ~new_n33_;
  assign new_n35_ = ~new_n29_ & new_n34_;
  assign new_n36_ = ~new_n19_ & new_n27_;
  assign new_n37_ = new_n14_ & ~new_n36_;
  assign new_n38_ = ~new_n28_ & ~new_n37_;
  assign o = new_n35_ | new_n38_;
endmodule


