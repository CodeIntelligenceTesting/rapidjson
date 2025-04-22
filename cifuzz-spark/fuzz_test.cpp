#include <assert.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

// RapidJSON includes
#include "rapidjson/document.h"
#include "rapidjson/schema.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/error/en.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

// FUZZ_TEST_SETUP:
// (No one-time setup needed beyond what is shown)
FUZZ_TEST_SETUP() {
  // One-time initialization tasks can be performed here.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider (using a single instance)
  FuzzedDataProvider fdp(data, size);

  // Consume a string for the schema (limit size to 1024)
  std::string schemaStr = fdp.ConsumeRandomLengthString(1024);
  // Consume remaining data for the JSON instance (limit to 8192)
  std::string jsonStr = fdp.ConsumeRandomLengthString(8192);

  // ----------------------------- //
  // Set up the Schema using tmpfile
  // ----------------------------- //
  FILE* schemaFile = tmpfile();
  if (!schemaFile) return; // if tmpfile fails, exit

  // Write schema data to file
  if (!schemaStr.empty()) {
      fwrite(schemaStr.data(), 1, schemaStr.size(), schemaFile);
  }
  rewind(schemaFile);

  // Prepare a buffer, and parse the schema using FileReadStream
  char buffer[4096];
  rapidjson::Document d;
  rapidjson::FileReadStream schemaStream(schemaFile, buffer, sizeof(buffer));
  d.ParseStream(schemaStream);
  fclose(schemaFile);

  // Construct the SchemaDocument from the parsed Document
  rapidjson::SchemaDocument sd(d);

  // --------------------------------- //
  // Set up JSON instance using tmpfile
  // --------------------------------- //
  FILE* jsonFile = tmpfile();
  if (!jsonFile) return;

  if (!jsonStr.empty()) {
      fwrite(jsonStr.data(), 1, jsonStr.size(), jsonFile);
  }
  rewind(jsonFile);

  // Create a SchemaValidator and Reader.
  rapidjson::SchemaValidator validator(sd);
  rapidjson::Reader reader;
  rapidjson::FileReadStream jsonStream(jsonFile, buffer, sizeof(buffer));
  reader.Parse(jsonStream, validator);
  fclose(jsonFile);

  // Call additional API functions to further exercise the interface.
  volatile bool valid = validator.IsValid();
  // When invalid, obtain various API outputs
  if (!valid) {
      rapidjson::GenericStringBuffer<rapidjson::UTF8<>> sb;
      validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
      validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
      rapidjson::PrettyWriter<rapidjson::GenericStringBuffer<rapidjson::UTF8<>>> writer(sb);
      validator.GetError().Accept(writer);
  }
}