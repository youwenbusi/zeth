/**
 *****************************************************************************
 * @author     This file is part of libfqfft, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <memory>
#include <vector>

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <stdint.h>

#include <libfqfft/evaluation_domain/domains/basic_radix2_domain.hpp>
#include <libfqfft/evaluation_domain/domains/extended_radix2_domain.hpp>
#include <libfqfft/tools/exceptions.hpp>

namespace libfqfft {

  /**
   * Note: Templatized type referenced with TypeParam (instead of canonical FieldT)
   * https://github.com/google/googletest/blob/master/googletest/docs/AdvancedGuide.md#typed-tests
   */
  template <typename T>
  class EvaluationDomainTest : public ::testing::Test {
    protected:
      virtual void SetUp() {
        libff::alt_bn128_pp::init_public_params();
      }
  };

  template<typename FieldT>
  FieldT evaluate_polynomial(const size_t &m, const std::vector<FieldT> &coeff, const FieldT &t)
  {
    if (m != coeff.size()) throw DomainSizeException("expected m == coeff.size()");

    FieldT result = FieldT::zero();
    /**
     * NB: unsigned reverse iteration: cannot do i >= 0, but can do i < m
     * because unsigned integers are guaranteed to wrap around
     */
    for (size_t i = m - 1; i < m; i--)
    {
      result = (result * t) + coeff[i];
    }

    return result;
  }

  typedef ::testing::Types<libff::Fr<libff::alt_bn128_pp>, libff::Double> FieldT; /* List Extend Here */
  TYPED_TEST_CASE(EvaluationDomainTest, FieldT);

  TYPED_TEST(EvaluationDomainTest, FFT) {

    const size_t m = 4;
    std::vector<TypeParam> f = { 2, 5, 3, 8 };

    std::shared_ptr<evaluation_domain<TypeParam> > domain;
    for (int key = 0; key < 2; key++)
    {
      try
      {
        if (key == 0) domain.reset(new basic_radix2_domain<TypeParam>(m));
        else if (key == 1) domain.reset(new extended_radix2_domain<TypeParam>(m));

        std::vector<TypeParam> a(f);
        domain->FFT(a);

        std::vector<TypeParam> idx(m);
        for (size_t i = 0; i < m; i++)
        {
          idx[i] = domain->get_domain_element(i);
        }

        for (size_t i = 0; i < m; i++)
        {
          TypeParam e = evaluate_polynomial(m, f, idx[i]);
          EXPECT_TRUE(e == a[i]);
        }
      }
      catch(DomainSizeException &e)
      {
        printf("%s - skipping\n", e.what());
      }
      catch(InvalidSizeException &e)
      {
        printf("%s - skipping\n", e.what());
      }
    }
  }

  TYPED_TEST(EvaluationDomainTest, InverseFFTofFFT) {

    const size_t m = 4;
    std::vector<TypeParam> f = { 2, 5, 3, 8 };

    std::shared_ptr<evaluation_domain<TypeParam> > domain;
    for (int key = 0; key < 2; key++)
    {
      try
      {
        if (key == 0) domain.reset(new basic_radix2_domain<TypeParam>(m));
        else if (key == 1) domain.reset(new extended_radix2_domain<TypeParam>(m));

        std::vector<TypeParam> a(f);
        domain->FFT(a);
        domain->iFFT(a);

        for (size_t i = 0; i < m; i++)
        {
          EXPECT_TRUE(f[i] == a[i]);
        }
      }
      catch(const DomainSizeException &e)
      {
        printf("%s - skipping\n", e.what());
      }
      catch(const InvalidSizeException &e)
      {
        printf("%s - skipping\n", e.what());
      }
    }
  }

  TYPED_TEST(EvaluationDomainTest, InverseCosetFFTofCosetFFT) {

    const size_t m = 4;
    std::vector<TypeParam> f = { 2, 5, 3, 8 };

    TypeParam coset = TypeParam::multiplicative_generator;

    std::shared_ptr<evaluation_domain<TypeParam> > domain;
    for (int key = 0; key < 2; key++)
    {
      try
      {
        if (key == 0) domain.reset(new basic_radix2_domain<TypeParam>(m));
        else if (key == 1) domain.reset(new extended_radix2_domain<TypeParam>(m));

        std::vector<TypeParam> a(f);
        domain->cosetFFT(a, coset);
        domain->icosetFFT(a, coset);

        for (size_t i = 0; i < m; i++)
        {
          EXPECT_TRUE(f[i] == a[i]);
        }
      }
      catch(const DomainSizeException &e)
      {
        printf("%s - skipping\n", e.what());
      }
      catch(const InvalidSizeException &e)
      {
        printf("%s - skipping\n", e.what());
      }
    }
  }

  TYPED_TEST(EvaluationDomainTest, ComputeZ) {

    const size_t m = 8;
    TypeParam t = TypeParam(10);

    std::shared_ptr<evaluation_domain<TypeParam> > domain;
    for (int key = 0; key < 2; key++)
    {
      try
      {
        if (key == 0) domain.reset(new basic_radix2_domain<TypeParam>(m));
        else if (key == 1) domain.reset(new extended_radix2_domain<TypeParam>(m));

        TypeParam a;
        a = domain->compute_vanishing_polynomial(t);

        TypeParam Z = TypeParam::one();
        for (size_t i = 0; i < m; i++)
        {
          Z *= (t - domain->get_domain_element(i));
        }

        EXPECT_TRUE(Z == a);
      }
      catch(const DomainSizeException &e)
      {
        printf("%s - skipping\n", e.what());
      }
      catch(const InvalidSizeException &e)
      {
        printf("%s - skipping\n", e.what());
      }
    }
  }

} // libfqfft
