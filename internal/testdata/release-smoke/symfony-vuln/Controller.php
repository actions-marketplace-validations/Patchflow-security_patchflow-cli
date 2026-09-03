<?php
// Symfony vulnerable fixture: DQL with string concatenation.
// PF-SYMFONY-SQLI-002 should fire on the createQuery with concatenation.

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Doctrine\ORM\EntityManagerInterface;

class UserController extends AbstractController
{
    public function search(Request $request, EntityManagerInterface $em)
    {
        $name = $request->query->get('name');
        // VULNERABLE: DQL with string concatenation
        $users = $em->createQuery("SELECT u FROM App\Entity\User u WHERE u.name = '" . $name . "'")
            ->getResult();
        return new Response(json_encode($users));
    }

    public function redirect(Request $request)
    {
        $url = $request->query->get('url');
        // VULNERABLE: open redirect
        return new \Symfony\Component\HttpFoundation\RedirectResponse($url);
    }
}
