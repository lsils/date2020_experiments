## *A Logic Synthesis Toolbox for Reducing the Multiplicative Complexity in Logic Networks* 

Experiments for DATE 2020: 

### Installation

* Clone and build `abc`: https://github.com/berkeley-abc/abc (required for combinational equivalence checking)
* Add the path to the executable of `abc` to your PATH variable
* Clone `mockturtle`: https://github.com/lsils/mockturtle (this work has been evaluated using `mockturtle` from commit )
* Add the files from this repository to the experiments folder of `mockturtle`
* Build `mockturtle` with experiments: 

```
cd mockturtle
mkdir build
cd build
cmake -DMOCKTURTLE_TEST=ON -DMOCKTURTLE_EXPERIMENTS=ON ..
make
```

* Run the experiments from the build folder of `mockturtle`: 

```
./experiments/xag_minmc ../experiments/db 
```

Running all the experiments will require some time. The number of experiments can be changed by changing the xag_minmc.cpp file. 

This experiment will produce the last column (complete flow) of Table 1 and Table 2 from [TSRAD20]. 

### Reference

These results are described in the paper: [TSRAD20] Eleonora Testa, Mathias Soeken, Heinz Riener, Luca Amaru and Giovanni De Micheli, *A Logic Synthesis Toolbox for Reducing the
Multiplicative Complexity in Logic Networks*, in *DATE* 2020.

More on the same topic can be found in: [TSAD] Eleonora Testa, Mathias Soeken, Luca Amaru and Giovanni De Micheli, *Reducing the multiplicative complexity in logic networks for cryptography and security applications*, in *DAC* 2019. 