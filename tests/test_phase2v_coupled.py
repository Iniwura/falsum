"""Phase 2V couples opposite contexts in a real differentiable objective."""
import copy
import math
import unittest
from unittest.mock import patch

from falsum.phase2v_coupled import CoupledError, _numerical_loss, build_families
from falsum.phase2u_context_transfer import make_context_pairs
from test_phase2u_context_transfer import fixtures


def sp(x):
    return math.log1p(math.exp(-abs(x)))+max(0,x)


class CoupledLossTests(unittest.TestCase):
    def setUp(self):
        self.pub,self.key,self.old,self.train,self.prior=fixtures()
        _,self.manifest=make_context_pairs(self.pub,self.key,self.old,self.train,self.prior)

    def test_four_project_opposite_context_pairs_and_zero_release(self):
        families=build_families(self.pub,self.key,self.manifest,self.train,self.old,self.prior)
        self.assertEqual(len(families),4)
        self.assertEqual(len({x["id"] for x in families}),4)
        self.assertFalse(self.manifest["network_eligible"])
        self.assertEqual(self.manifest["independent_human_reviews"],0)
        for family in families:
            self.assertNotEqual(family["exposure_prompt"],family["missing_prompt"])
            self.assertNotEqual(family["finding_answer"],family["conditional_answer"])
            self.assertTrue(len(family["finding_answer"])>100)

    def test_coupled_margin_objective_prefers_both_correct_directions(self):
        kwargs={"target":0.3,"contrast_weight":1.0,"neutral_weight":0.1,"softplus":sp}
        correct=_numerical_loss(1.0,-1.0,0.0,**kwargs)
        always_finding=_numerical_loss(1.0,1.0,0.0,**kwargs)
        always_conditional=_numerical_loss(-1.0,-1.0,0.0,**kwargs)
        zero=_numerical_loss(0.0,0.0,0.0,**kwargs)
        self.assertLess(correct,always_finding)
        self.assertLess(correct,always_conditional)
        self.assertLess(correct,zero)

    def test_answer_only_shortcut_is_penalized(self):
        args={"target":0.3,"contrast_weight":0.6,"neutral_weight":0.2,"softplus":sp}
        self.assertGreater(_numerical_loss(0.8,-0.7,2.0,**args),
                           _numerical_loss(0.8,-0.7,0.0,**args))

    def test_loss_enforces_cross_context_coupling_beyond_single_context_wins(self):
        args={"target":0.2,"contrast_weight":2.0,"neutral_weight":0.0,"softplus":sp}
        near=_numerical_loss(0.01,-0.01,0,**args)
        confident=_numerical_loss(1.1,-1.1,0,**args)
        self.assertGreater(near,confident)

    def test_bounded_experimental_parameters(self):
        for values in ((0,0.5,0.1),(.3,0,0.1),(.3,0.5,-0.1),
                       (3,1,0),(.3,1,3)):
            with self.subTest(values=values),self.assertRaises(CoupledError):
                _numerical_loss(0,0,0,target=values[0],contrast_weight=values[1],
                                neutral_weight=values[2],softplus=sp)

    def test_training_on_first_four_diagnostic_projects_refused(self):
        swapped=copy.deepcopy(self.train)
        swapped["cases"][0]["repository"]=self.old["cases"][0]["repository"]
        with self.assertRaises(ValueError):
            build_families(self.pub,self.key,self.manifest,swapped,self.old,self.prior)

    def test_fake_network_eligibility_or_expert_review_rejected(self):
        for field,val in (("network_eligible",True),("independent_human_reviews",1),
                          ("status","NETWORK_APPROVED")):
            with self.subTest(field=field):
                m=copy.deepcopy(self.manifest);m[field]=val
                with self.assertRaises(CoupledError):
                    build_families(self.pub,self.key,m,self.train,self.old,self.prior)

    def test_missing_context_or_swapped_key_rejected(self):
        pub=copy.deepcopy(self.pub)
        pub["cases"][0]["case_id"]=pub["cases"][1]["case_id"]
        with self.assertRaises(ValueError):
            build_families(pub,self.key,self.manifest,self.train,self.old,self.prior)

    def test_torch_gradient_direction_when_available(self):
        try:
            import torch
        except ImportError:
            self.skipTest("official trainer torch not installed in offline foundation")
        ex=torch.tensor(0.03,requires_grad=True)
        no=torch.tensor(0.03,requires_grad=True)
        ans=torch.tensor(1.0,requires_grad=True)
        loss=_numerical_loss(ex,no,ans,target=0.3,contrast_weight=0.8,
                             neutral_weight=0.1,softplus=torch.nn.functional.softplus)
        loss.backward()
        self.assertLess(ex.grad.item(),0) # update should INCREASE exposure finding margin
        self.assertGreater(no.grad.item(),0) # update should DECREASE missing-context finding margin
        self.assertGreater(ans.grad.item(),0) # penalize answer-only shortcut


if __name__=="__main__":
    unittest.main()
