/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2020 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#pragma once

#include <protocol/unsigned_leb128.h>

#include <protocol/client_opcode.hxx>
#include <operations/document_id.hxx>

namespace couchbase::protocol
{

class remove_response_body
{
  public:
    static const inline client_opcode opcode = client_opcode::remove;

    mutation_token token_;

  public:
    mutation_token& token()
    {
        return token_;
    }

    bool parse(protocol::status, const header_buffer& header, const std::vector<uint8_t>& body, const cmd_info&)
    {
        Expects(header[1] == static_cast<uint8_t>(opcode));
        using offset_type = std::vector<uint8_t>::difference_type;
        uint8_t ext_size = header[4];
        offset_type offset = 0;
        if (ext_size == 16) {
            memcpy(&token_.partition_uuid, body.data() + offset, sizeof(token_.partition_uuid));
            token_.partition_uuid = utils::byte_swap_64(token_.partition_uuid);
            offset += 8;

            memcpy(&token_.sequence_number, body.data() + offset, sizeof(token_.sequence_number));
            token_.sequence_number = utils::byte_swap_64(token_.sequence_number);
        }
        return false;
    }
};

class remove_request_body
{
  public:
    using response_body_type = remove_response_body;
    static const inline client_opcode opcode = client_opcode::remove;

  private:
    std::string key_;

  public:
    void id(const operations::document_id& id)
    {
        key_ = id.key;
        if (id.collection_uid) {
            unsigned_leb128<uint32_t> encoded(*id.collection_uid);
            key_.insert(0, encoded.get());
        }
    }

    const std::string& key()
    {
        return key_;
    }

    const std::vector<std::uint8_t>& extension()
    {
        static std::vector<std::uint8_t> empty;
        return empty;
    }

    const std::vector<std::uint8_t>& value()
    {
        static std::vector<std::uint8_t> empty;
        return empty;
    }

    std::size_t size()
    {
        return key_.size();
    }
};

} // namespace couchbase::protocol
