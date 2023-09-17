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
#include <fstream>
#include <string>
#include "torch/script.h"
#include "torch/torch.h"
#include <iostream>
#include <map>
#include <sstream>
#include <cstring>
#include <vector>
#include <istream>
#include <unordered_map>

using namespace snort;
using Vocab = std::unordered_map<std::string, size_t>;

#define SUNLIT_GID 247
#define SUNLIT_SID 1

static const char* s_name = "sunlit";
static const char* s_help = "Sunlit Deep Learning Inspector";

static THREAD_LOCAL ProfileStats sunlitPerfStats;

static THREAD_LOCAL SimpleStats sunlitstats;

THREAD_LOCAL const Trace* sunlit_trace = nullptr;


//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class WordpieceTokenizer {
public:
    std::pair<torch::Tensor, torch::Tensor> tokenize(const std::string& text) const;
    std::shared_ptr<Vocab> mVocab;
    std::shared_ptr<Vocab> loadVocab(const std::string& vocabFile);

private:
    std::vector<std::string> split(const std::string& s) const;
};

class Sunlit : public Inspector
{
public:
    Sunlit(const std::string& pytorch_model_path, const std::string& tokenizer_path);
    void show(const SnortConfig*) const override;
    void eval(Packet*) override;    

private:
    std::string string_to_ngrams(const std::string& s);
    bool to_hex(char* dest, size_t dest_len, const uint8_t* values, size_t val_len);
    torch::jit::script::Module module;
    WordpieceTokenizer pBertTokenizer;
    
};

Sunlit::Sunlit(const std::string& pytorch_model_path, const std::string& tokenizer_path)
{

    std::string pytorch_model = pytorch_model_path;
    module = torch::jit::load(pytorch_model_path);

    pBertTokenizer = WordpieceTokenizer();
    std::shared_ptr<Vocab> mVocab = pBertTokenizer.loadVocab(tokenizer_path);
    pBertTokenizer.mVocab = mVocab;
    
}

void Sunlit::show(const SnortConfig*) const
{
    
}

std::vector<std::string> WordpieceTokenizer::split(const std::string& s) const {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;

    while (getline (ss, item, ' ')) {
        result.push_back (item);
    }

    return result;
}

std::pair<torch::Tensor, torch::Tensor> WordpieceTokenizer::tokenize(const std::string& text) const {
    std::vector<std::string> outputTokens;
    std::string ltext(text);
    int max_length = 512;

    int pad_token_id = (*mVocab)["[PAD]"], start_token_id = (*mVocab)["[CLS]"], end_token_id = (*mVocab)["[SEP]"];

    for (auto& x : ltext) {
        x = std::tolower(x);
    }

    std::vector<std::string> splitTokens = split(ltext);

    for (auto& token : splitTokens) {
       
        bool isBad = false;
        size_t start = 0;
        std::vector<std::string> subTokens;
        while (start < token.size()) {
            size_t end = token.size();
            std::string curSubstr;
            bool hasCurSubstr = false;
            while (start < end) {
                std::string substr = token.substr(start, end - start);
                if (start > 0) substr = "##" + substr;
                if (mVocab->find(substr) != mVocab->end()) {
                    curSubstr = substr;
                    hasCurSubstr = true;
                    break;
                }
                end--;
            }
            if (!hasCurSubstr) {
                isBad = true;
                break;
            }
            subTokens.push_back(curSubstr);
            start = end;
        }
        if (isBad) outputTokens.push_back("[UNK]");
        else outputTokens.insert(outputTokens.end(), subTokens.begin(), subTokens.end());
        if (outputTokens.size() >= max_length - 2)
        {
            outputTokens.resize(max_length - 2);
            break;
        }
    }

    std::vector<int> input_ids(max_length, pad_token_id), masks(max_length, 0);
    input_ids[0] = start_token_id; masks[0] = 1;

    for (int i = 1; i <= outputTokens.size(); i++) {

        input_ids[i] = (*mVocab)[outputTokens[i - 1]];
        masks[i] = 1;
    }
    
    int input_id = outputTokens.size() + 1; 
    masks[input_id] = 1;
    input_ids[input_id] = end_token_id;

    auto input_ids_tensor = torch::tensor(input_ids).unsqueeze(0);
    auto masks_tensor = torch::tensor(masks).unsqueeze(0);

    return std::make_pair(input_ids_tensor, masks_tensor);
}

bool Sunlit::to_hex(char* dest, size_t dest_len, const uint8_t* values, size_t val_len) {

    if(dest_len < (val_len*2+1)) 
        return false;
    
    *dest = '\0'; 
    while(val_len--) {
        
        sprintf(dest, "%02X", *values);
        dest += 2;
        ++values;
    }
    return true;
}

std::shared_ptr<Vocab> WordpieceTokenizer::loadVocab(const std::string& vocabFile) {
    std::shared_ptr<Vocab> vocab(new Vocab);
    size_t index = 0;
    std::ifstream ifs(vocabFile, std::ifstream::in);
    if (!ifs) {
        throw std::runtime_error("open file failed");
    }
    std::string token;
    while (getline(ifs, token)) {
         if (token.empty()) break;
        (*vocab)[token] = index;
        index++;
    }
    return vocab;
}

std::string Sunlit::string_to_ngrams(const std::string& s)
{
    std::string tempstr;
    std::string result;
    const auto s_size = s.size();
    result.reserve(s_size + (s_size * 5));
    tempstr.append(s);
    tempstr.append("0000");
    for (int i = 0; i < s_size - 2; i++) {
        result += tempstr.substr(i, 5) + " ";
    }
    result += tempstr.substr(tempstr.length() - 5, 5);
    return result;
}

void Sunlit::eval(Packet* p)
{

    char buffer[p->pktlen*2+1]; /* one extra for \0 */
    
    if(to_hex(buffer, sizeof(buffer), p->pkt, p->pktlen))
    {

        std::string payload(buffer);
        std::string text = string_to_ngrams(payload);

        torch::Tensor input_ids_tensor, masks_tensor;
        std::tie(input_ids_tensor, masks_tensor) = pBertTokenizer.tokenize(text);
   
        std::vector<torch::jit::IValue> inputs;
        inputs.push_back(input_ids_tensor);
        inputs.push_back(masks_tensor);

        auto outputs = module.forward(inputs).toTuple()->elements()[0].toTensor();
        
        if (outputs.argmax().item<int>() == 1)
        {
            DetectionEngine::queue_event(SUNLIT_GID, SUNLIT_SID);
        }
        
    }
    ++sunlitstats.total_packets;      
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter sunlit_params[] =
{
    { "pytorch_model_path", Parameter::PT_STRING, nullptr, nullptr,
        "Path of Pytorch model" },

    { "tokenizer_path", Parameter::PT_STRING, nullptr, nullptr,
        "Path of tokenizer vocabulary file" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap sunlit_rules[] =
{
    { SUNLIT_SID, "A suspicious code was detected by Artificial Inteligent inspection" },
    { 0, nullptr }
};

class SunlitModule : public Module
{
public:
    SunlitModule() : Module(s_name, s_help, sunlit_params)
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

    bool set(const char*, Value& v, SnortConfig*) override;

    Usage get_usage() const override
    { return INSPECT; }

    void set_trace(const Trace*) const override;
    const TraceOption* get_trace_options() const override;

public:
    std::string pytorch_model_path;
    std::string tokenizer_path;

};

bool SunlitModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("pytorch_model_path") )
        pytorch_model_path = v.get_string();

    else if ( v.is("tokenizer_path") )
        tokenizer_path = v.get_string();

    return true;
}

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
    return new Sunlit(mod->pytorch_model_path, mod->tokenizer_path);
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
