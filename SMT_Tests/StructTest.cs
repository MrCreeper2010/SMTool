using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SMT_Tests
{
    struct StructTest
    {
        public int? FRANCUS;

        public int fr 
        { 
            get 
            { 
                return FRANCUS ?? 42; 
            } 
            set 
            { 
                FRANCUS = value; 
            } 
        }
    }
}
