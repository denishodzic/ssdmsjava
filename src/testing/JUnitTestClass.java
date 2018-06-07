package testing;

import org.junit.*;
//import prod.CertTransparencyGood;

import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;

public class JUnitTestClass {

    @BeforeClass
    // runs only once, MUST be static
    public static void BeforeClass(){

    }

    @Before
    // runs before each test
    public void before(){

    }

    @Test
    public void test() throws Exception {
    System.out.println("I am Test 1");
    //CertTransparencyGood certTransparencyGood = new CertTransparencyGood();
    //assertEquals( false, certTransparencyGood.sendGet("weberdns.de") );
    }

    @After
    // runs after each test
    public void after(){

    }

    @AfterClass
    // runs only once, MUST be static
    public static void AfterClass(){

    }
}
