function getValueFacet(aggregations, fieldName) {
  if (
    aggregations &&
    aggregations[fieldName] &&
    aggregations[fieldName].buckets &&
    aggregations[fieldName].buckets.length > 0
  ) {
    return [
      {
        field: fieldName,
        type: "value",
        data: aggregations[fieldName].buckets.map(bucket => ({
          // Boolean values and date values require using `key_as_string`
          value: bucket.key_as_string || bucket.key,
          count: bucket.doc_count
        }))
      }
    ];
  }
}

function getRangeFacet(aggregations, fieldName) {
  if (
    aggregations &&
    aggregations[fieldName] &&
    aggregations[fieldName].buckets &&
    aggregations[fieldName].buckets.length > 0
  ) {
    return [
      {
        field: fieldName,
        type: "range",
        data: aggregations[fieldName].buckets.map(bucket => ({
          // Boolean values and date values require using `key_as_string`
          value: {
            to: bucket.to,
            from: bucket.from,
            name: bucket.key
          },
          count: bucket.doc_count
        }))
      }
    ];
  }
}

export default function buildStateFacets(aggregations) {
  const brief = getValueFacet(aggregations, "brief");
  const name = getValueFacet(
    aggregations,
    "name"
  );
  // const visitors = getRangeFacet(aggregations, "visitors");
  // const acres = getRangeFacet(aggregations, "acres");

  const facets = {
    ...(brief && { brief }),
    ...(name && { name }),
    // ...(visitors && { visitors }),
    // ...(acres && { acres })
  };

  if (Object.keys(facets).length > 0) {
    return facets;
  }
}
