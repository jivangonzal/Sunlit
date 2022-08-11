//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// sunlit.cc 

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "radish/utils/text_tokenizer.h"
#include <fstream>
#include <string>
#include <cstddef>
#include "torch/script.h"
#include <iostream>



using namespace snort;

#define SUNLIT_GID 256
#define SUNLIT_SID 2

static const char* s_name = "sunlit";
static const char* s_help = "Sunlit Deep Learning Inspector";

static THREAD_LOCAL ProfileStats sunlitPerfStats;

static THREAD_LOCAL SimpleStats sunlitstats;

THREAD_LOCAL const Trace* sunlit_trace = nullptr;


//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Sunlit : public Inspector
{
public:
    Sunlit();
    void show(const SnortConfig*) const override;
    void eval(Packet*) override;
    

private:
    int max_len = 128;
    bool to_hex(char* dest, size_t dest_len, const uint8_t* values, size_t val_len);
    std::string chunk_string(const std::string& s, const std::size_t chunk_size = 4U, const char delimiter = ' ');
    void preprocess(string text, vector<float> &input_ids, vector<float> &input_mask);
    std::unique_ptr<radish::TextTokenizer> tokenizer_;
    torch::jit::script::Module module;
};

Sunlit::Sunlit()
{
    std::string pytorch_model = "/home/jigonzal/traced_resnet_model.pt";
    module = torch::jit::load(pytorch_model);

    tokenizer_.reset(radish::TextTokenizerFactory::Create("radish::BertTokenizer"));
    tokenizer_->Init("/home/jigonzal/snort-source-files/snort3_extra-3.1.25.0/radish/bert/data/bert-base-uncased-vocab.txt");
}

void Sunlit::show(const SnortConfig*) const
{
    
}

bool Sunlit::to_hex(char* dest, size_t dest_len, const uint8_t* values, size_t val_len) {

    if(dest_len < (val_len*2+1)) /* check that dest is large enough */
        return false;
    
    *dest = '\0'; /* in case val_len==0 */
    while(val_len--) {
        /* sprintf directly to where dest points */
        sprintf(dest, "%02X", *values);
        dest += 2;
        ++values;
    }
    return true;
}

void Sunlit::preprocess(string text, vector<float> &input_ids, vector<float> &input_mask)
{
    vector<string> tokens;
    tokenize(text,tokens,valid_positions);
    // insert "[CLS}"
    tokens.insert(tokens.begin(),"[CLS]");
    valid_positions.insert(valid_positions.begin(),1.0);
    // insert "[SEP]"
    tokens.push_back("[SEP]");
    valid_positions.push_back(1.0);
    for(int i = 0; i < tokens.size(); i++)
    {
        segment_ids.push_back(0.0);
        input_mask.push_back(1.0);
    }
    input_ids = tokenizer.convert_tokens_to_ids(tokens);
    while(input_ids.size() < max_len)
    {
        input_ids.push_back(0.0);
        input_mask.push_back(0.0);
    }
}

std::string Sunlit::chunk_string(const std::string& s, const std::size_t chunk_size, const char delimiter) 
{
    std::string result;
    const auto s_size = s.size();
    result.reserve(s_size + (s_size / chunk_size));

    for (std::size_t i = 0U; i < s_size; i += chunk_size) {
        result += s.substr(i, chunk_size);
        if (i + chunk_size < s_size) { 
            result += delimiter; 
        }
    }
    return result;
}

void Sunlit::eval(Packet* p)
{
    
    
    auto ids = tokenizer_->Encode("This is only a test");
    for (auto v : ids)
    {
        std::string valu = std::to_string(v);
        const char * tex = valu.c_str();
        WarningMessage(tex);
    }

    return;


    
    try {

    
        // Create a vector of inputs.
        std::vector<torch::jit::IValue> inputs;
        inputs.push_back(torch::ones({1, 3, 224, 224}));

        // Execute the model and turn its output into a tensor.
        at::Tensor output = module.forward(inputs).toTensor();
        //WarningMessage(output.slice(1, 0, 5));
        //std::string otext = output.slice(/*dim=*/1, /*start=*/0, /*end=*/5);

        double d1 = output[0][0].item<double>();
        double d2 = output[0][1].item<double>();
        double d3 = output[0][2].item<double>();
        double d4 = output[0][3].item<double>();
        double d5 = output[0][4].item<double>();

        std::string mess = std::to_string(d1) + " " + std::to_string(d2) + " " + std::to_string(d3) + " " + std::to_string(d4) + " " + std::to_string(d5);
        int n = mess.length();
 
        // declaring character array
        char char_array[n + 1];
    
        // copying the contents of the
        // string to char array
        strcpy(char_array, mess.c_str());

        WarningMessage(char_array);
    }
    catch (const c10::Error& e) {
        WarningMessage("error loading the model");
        
        return;
    }

    return;
    
    char buffer[p->pktlen*2+1]; /* one extra for \0 */

    if(to_hex(buffer, sizeof(buffer), p->pkt, p->pktlen))
    {
        std::fstream myfile;
        myfile = std::fstream("file.hex", std::fstream::out | std::fstream::app);
        myfile.write(buffer, strlen(buffer));
    }


    //trace_logf(sunlit_trace, p, "destination port: %d, packet payload size: %d.\n",
    //    p->ptrs.dp, p->dsize);


    DetectionEngine::queue_event(SUNLIT_GID, SUNLIT_SID);


    ++sunlitstats.total_packets;
    //WarningMessage("destination port: %d, packet payload size: %d.\n",
    //        p->ptrs.dp, p->dsize);
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const RuleMap sunlit_rules[] =
{
    { SUNLIT_SID, "A suspicious code was detected by Artificial Inteligent inspection" },
    { 0, nullptr }
};

class SunlitModule : public Module
{
public:
    SunlitModule() : Module(s_name, s_help)
    { }

    unsigned get_gid() const override
    { return SUNLIT_GID; }

    const RuleMap* get_rules() const override
    { return sunlit_rules; }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&sunlitstats; }

    ProfileStats* get_profile() const override
    { return &sunlitPerfStats; }

    Usage get_usage() const override
    { return INSPECT; }

    void set_trace(const Trace*) const override;
    const TraceOption* get_trace_options() const override;


};


void SunlitModule::set_trace(const Trace* trace) const
{ sunlit_trace = trace; }

const TraceOption* SunlitModule::get_trace_options() const
{
    static const TraceOption sunlit_options(nullptr, 0, nullptr);
    return &sunlit_options;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SunlitModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* sunlit_ctor(Module* m)
{
    SunlitModule* mod = (SunlitModule*)m;
    return new Sunlit();
}

static void sunlit_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi sunlit_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PROBE,
    PROTO_BIT__ANY_IP | PROTO_BIT__ETH,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    sunlit_ctor,
    sunlit_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &sunlit_api.base,
    nullptr
};