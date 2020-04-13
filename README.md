## *A Logic Synthesis Toolbox for Reducing the Multiplicative Complexity in Logic Networks* 

Experiments for DATE 2020: 

### Installation

* Clone and build `abc`: https://github.com/berkeley-abc/abc (required for combinational equivalence checking)
* Add the path to the executable of `abc` to your PATH variable
* Clone `mockturtle`: https://github.com/lsils/mockturtle (see Final Remark)
* Add the files from this repository to the experiments folder of `mockturtle`
* Build `mockturtle` with experiments: 

```
cd mockturtle
mkdir build
cd build
cmake -DMOCKTURTLE_TEST=ON -DMOCKTURTLE_EXPERIMENTS=ON -DCMAKE_BUILD_TYPE=Release ..
make
```

* Run the experiments from the build folder of `mockturtle`: 

```
./experiments/xag_minmc ../experiments/db 
```

Running all the experiments will require some time. The number of experiments can be changed by changing the xag_minmc.cpp file. 
This experiment will produce the last column (complete flow) of Table 1 and Table 2 from [1]. 

To obtain Table 3 from [1], run: 

```
./experiments/xag_minmc_MPC ../experiments/db 
```

### Benchmarks 

We apply our algorithm both on benchmarks coming from [2] and from [3]. 

### Reference

[1] These results are described in the paper: [TSRAD20](https://msoeken.github.io/papers/2020_date.pdf) Eleonora Testa, Mathias Soeken, Heinz Riener, Luca Amarù and Giovanni De Micheli, *A Logic Synthesis Toolbox for Reducing the
Multiplicative Complexity in Logic Networks*, in *DATE* 2020.

[2] More on the same topic can be found in: [TSAD19](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8806905) Eleonora Testa, Mathias Soeken, Luca Amarù and Giovanni De Micheli, *Reducing the multiplicative complexity in logic networks for cryptography and security applications*, in *DAC* 2019. The experiments and benchmarks are available at: https://github.com/eletesta/dac19-experiments

[3] The MPC benchmarks can be found in: [MPC19](https://eprint.iacr.org/2019/275.pdf) M. Sadegh Riazi, Mojan Javaheripi, Siam U. Hussain, Farinaz Koushanfar, *MPCircuits: Optimized circuit generation for secure multi-party computation*, in *HOST* 2019. They are available at: https://github.com/sadeghriazi/MPCircuits

### Final Remark

Note that many changes have been made in `mockturtle` since the implementation of this work, thus different results may be achieved. In order to obtain the same results and have the code running, clone from the pull request [#231](https://github.com/lsils/mockturtle/pull/231) and commit `510579a`