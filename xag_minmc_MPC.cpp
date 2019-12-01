/* mockturtle: C++ logic network library
 * Copyright (C) 2018-2019  EPFL
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string>
#include <vector>

#include <fmt/format.h>
#include <lorina/aiger.hpp>

#include <mockturtle/algorithms/cleanup.hpp>
#include <mockturtle/algorithms/cut_rewriting.hpp>
#include <mockturtle/algorithms/node_resynthesis/bidecomposition.hpp>
#include <mockturtle/algorithms/node_resynthesis/xag_minmc.hpp>
#include <mockturtle/algorithms/refactoring.hpp>
#include <mockturtle/algorithms/xag_resub_withDC.hpp>
#include <mockturtle/io/verilog_reader.hpp>
#include <mockturtle/networks/xag.hpp>

#include <experiments.hpp>

using namespace experiments;
using namespace mockturtle;

static const char* crypto_MPC_benchmarks[] = {
    "auction_N_2_W_16", "auction_N_2_W_32", "auction_N_3_W_16", "auction_N_3_W_32", "auction_N_4_W_16", "auction_N_4_W_32", 
    "knn_comb_K_1_N_8", "knn_comb_K_1_N_16", "knn_comb_K_2_N_8", "knn_comb_K_2_N_16", "knn_comb_K_3_N_8", "knn_comb_K_3_N_16", 
    "voting_N_1_M_3", "voting_N_1_M_4", "voting_N_2_M_2", "voting_N_2_M_3", "voting_N_2_M_4", "voting_N_3_M_4", 
    "stable_matching_comb_Ks_4_S_8", "stable_matching_comb_Ks_8_S_8"
    };

static const int crypto_MPC_area[] = {
    97, 194, 228, 454, 492, 975, 556, 1160, 1080, 2370, 1520, 3500, 8, 16, 37, 79, 147, 388, 16700, 46660};

std::vector<std::string> MPC_benchmarks( )
{
  std::vector<std::string> result;
  for ( uint32_t i = 0u; i < 1u; ++i ) // change this number to 20u to run also the stable matching benchmarks 
  {
      result.push_back( crypto_MPC_benchmarks[i] );
  }
  return result;
}

std::string MPC_benchmark_path( std::string const& benchmark_name )
{
#ifndef EXPERIMENTS_PATH
  return fmt::format( "{}.v", benchmark_name );
#else
  return fmt::format( "{}MPC_benchmarks/{}.v", EXPERIMENTS_PATH, benchmark_name );
#endif
}

template<class Ntk>
bool abc_cec_MPC( Ntk const& ntk, std::string const& benchmark )
{
  mockturtle::write_bench( ntk, "/tmp/test.bench" );
  std::string command = fmt::format( "abc -q \"cec -n {} /tmp/test.bench\"", MPC_benchmark_path( benchmark ) );

  std::array<char, 128> buffer;
  std::string result;
  std::unique_ptr<FILE, decltype( &pclose )> pipe( popen( command.c_str(), "r" ), pclose );
  if ( !pipe )
  {
    throw std::runtime_error( "popen() failed" );
  }
  while ( fgets( buffer.data(), buffer.size(), pipe.get() ) != nullptr )
  {
    result += buffer.data();
  }

  return result.size() >= 23 && result.substr( 0u, 23u ) == "Networks are equivalent";
}

namespace detail
{
template<class Ntk>
struct free_xor_cost
{
  uint32_t operator()( Ntk const& ntk, node<Ntk> const& n ) const
  {
    return ntk.is_xor( n ) ? 0 : 1;
  }
};

template<class Ntk>
struct mc_cost
{
  uint32_t operator()( Ntk const& ntk, node<Ntk> const& n ) const
  {
    return ntk.is_and( n ) ? 1 : 0;
  }
};
} // namespace detail*/

int main( int argc, char** argv )
{
  if ( argc <= 1 )
  {
    std::cout << "input shoudl be ''db [database]''\n";
    return 0;
  }

  experiment<std::string, uint32_t, uint32_t, float, uint32_t, float, bool> exp( "xag_minmc_MPC", "benchmark", "num_and", "num_and_opt", "improvement %", "iterations", "avg. runtime [s]", "equivalent" );

  auto k = 0u; 

  for ( auto const& benchmark : MPC_benchmarks() )
  {
    fmt::print( "[i] processing {}\n", benchmark );

    uint32_t num_and = 0u, num_xor = 0u; 
    float num_and_init = 0u;
    xag_network xag;
    lorina::read_verilog( MPC_benchmark_path( benchmark ), verilog_reader( xag ) );

    xag.foreach_gate( [&]( auto f ) {
      if ( xag.is_and( f ) )
      {
        num_and++;
      }
    } );
    xag.foreach_gate( [&]( auto f ) {
      if ( xag.is_xor( f ) )
      {
        num_xor++;
      }
    } );

    std::cout << " num and = " << num_and << std::endl;
    std::cout << " num xor = " << num_xor << std::endl;
    num_and_init = crypto_MPC_area[k]; 
    k++;

    uint32_t num_and_aft = num_and - 1;
    uint32_t num_xor_aft = 0u;

    cut_rewriting_params ps;
    ps.cut_enumeration_ps.cut_size = 6;
    ps.cut_enumeration_ps.cut_limit = 12;
    ps.verbose = true;
    ps.progress = false;
    ps.min_cand_cut_size = 2u;

    refactoring_params ps2;
    ps2.verbose = true;
    ps2.progress = false;
    ps2.allow_zero_gain = false;
    ps2.max_pis = 15;
    ps2.use_dont_cares = true;

    resubstitution_params ps3;
    ps3.max_divisors = 100;
    ps3.max_inserts = 4;
    ps3.max_pis = 8u;
    ps3.progress = false;
    ps3.verbose = true;
    ps3.use_dont_cares = true;

    xag_minmc_resynthesis resyn( argv[1] );
    bidecomposition_resynthesis<xag_network> resyn2;

    auto i = 0u;
    const clock_t begin_time = clock();

    while ( num_and > num_and_aft )
    {
      if ( i > 0 )
      {
        num_and = num_and_aft;
      }
      i++;
      num_and_aft = 0u;
      num_xor_aft = 0u;

      cut_rewriting( xag, resyn, ps, nullptr, ::detail::mc_cost<xag_network>() );
      xag = cleanup_dangling( xag );
      refactoring( xag, resyn2, ps2, nullptr, ::detail::free_xor_cost<xag_network>() );
      xag = cleanup_dangling( xag );
      using view_t = depth_view<fanout_view<xag_network>>;
      fanout_view<xag_network> fanout_view{xag};
      view_t resub_view{fanout_view};
      resubstitution_minmc_withDC( resub_view, ps3 );
      xag = cleanup_dangling( xag );

      xag.foreach_gate( [&]( auto f ) {
        if ( xag.is_and( f ) )
        {
          num_and_aft++;
        }
      } );
      xag.foreach_gate( [&]( auto f ) {
        if ( xag.is_xor( f ) )
        {
          num_xor_aft++;
        }
      } );
    }

    std::cout << " num and after = " << num_and_aft << std::endl;
    std::cout << " num xor after = " << num_xor_aft << std::endl;

    const auto cec = abc_cec_MPC( xag, benchmark );

    float impro = (( num_and_init - num_and_aft )/num_and_init) * 100; 
  
    exp( benchmark, num_and_init, num_and_aft, impro, i, (float( clock () - begin_time ) /  CLOCKS_PER_SEC) / i, cec );
  }

  exp.save();
  exp.table();

  return 0;
}
