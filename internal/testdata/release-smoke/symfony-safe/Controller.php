<?php
// Symfony safe fixture: parameterized Doctrine query with setParameter.
// The safe pattern "setParameter|->where\\(" should suppress
// PF-SYMFONY-SQLI-002 and TP-PHP001 -IP false positives.

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Doctrine\ORM\EntityManagerInterface;

class UserController extends AbstractController
{
    public function index(Request $request, EntityManagerInterface $em)
    {
        $name = $request->query->get('name');
        // SAFE: Doctrine DQL with setParameter
        $users = $em->createQuery('SELECT u FROM App\Entity\User u WHERE u.name = :name')
            ->setParameter('name', $name)
            ->getResult();
        return new Response(json_encode($users));
    }
}
