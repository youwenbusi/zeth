/**
 *****************************************************************************
 * @author     This file is part of libff, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <libff/common/profiling.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/fp12_2over3over2.hpp>
#include <libff/algebra/fields/fp6_3over2.hpp>

using namespace libff;

template<typename FieldT>
void test_field()
{
    bigint<1> rand1 = bigint<1>("76749407");
    bigint<1> rand2 = bigint<1>("44410867");
    bigint<1> randsum = bigint<1>("121160274");

    FieldT zero = FieldT::zero();
    FieldT one = FieldT::one();
    FieldT a = FieldT::random_element();
    FieldT a_ser;
    a_ser = reserialize<FieldT>(a);
    assert(a_ser == a);

    FieldT b = FieldT::random_element();
    FieldT c = FieldT::random_element();
    FieldT d = FieldT::random_element();

    assert(a != zero);
    assert(a != one);

    assert(a * a == a.squared());
    assert((a + b).squared() == a.squared() + a*b + b*a + b.squared());
    assert((a + b)*(c + d) == a*c + a*d + b*c + b*d);
    assert(a - b == a + (-b));
    assert(a - b == (-b) + a);

    assert((a ^ rand1) * (a ^ rand2) == (a^randsum));

    assert(a * a.inverse() == one);
    assert((a + b) * c.inverse() == a * c.inverse() + (b.inverse() * c).inverse());

}

template<typename FieldT>
void test_sqrt()
{
    for (size_t i = 0; i < 100; ++i)
    {
        FieldT a = FieldT::random_element();
        FieldT asq = a.squared();
        assert(asq.sqrt() == a || asq.sqrt() == -a);
    }
}

template<typename FieldT>
void test_Frobenius()
{
    FieldT a = FieldT::random_element();
    assert(a.Frobenius_map(0) == a);
    FieldT a_q = a ^ FieldT::base_field_char();
    for (size_t power = 1; power < 10; ++power)
    {
        const FieldT a_qi = a.Frobenius_map(power);
        assert(a_qi == a_q);

        a_q = a_q ^ FieldT::base_field_char();
    }
}

template<typename FieldT>
void test_unitary_inverse()
{
    assert(FieldT::extension_degree() % 2 == 0);
    FieldT a = FieldT::random_element();
    FieldT aqcubed_minus1 = a.Frobenius_map(FieldT::extension_degree()/2) * a.inverse();
    assert(aqcubed_minus1.inverse() == aqcubed_minus1.unitary_inverse());
}

template<typename ppT>
void test_all_fields()
{
    test_field<Fr<ppT> >();
    test_field<Fq<ppT> >();
    test_field<Fqe<ppT> >();
    test_field<Fqk<ppT> >();

    test_sqrt<Fr<ppT> >();
    test_sqrt<Fq<ppT> >();
    test_sqrt<Fqe<ppT> >();

    test_Frobenius<Fqe<ppT> >();
    test_Frobenius<Fqk<ppT> >();

    test_unitary_inverse<Fqk<ppT> >();
}

int main(void)
{
    alt_bn128_pp::init_public_params();
    test_field<alt_bn128_Fq6>();
    test_Frobenius<alt_bn128_Fq6>();
    test_all_fields<alt_bn128_pp>();
}
