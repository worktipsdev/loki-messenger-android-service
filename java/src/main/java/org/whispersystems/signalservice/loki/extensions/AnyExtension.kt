package org.whispersystems.signalservice.loki.extensions

import kotlin.reflect.KProperty1
import kotlin.reflect.full.memberProperties

/**
 * Get a private property from an instance
 * @receiver Any The property type
 * @param name String The name of the property
 * @return R The property
 */
@Suppress("UNCHECKED_CAST")
fun <R> Any.getPrivateProperty(name: String): R {
    val property = this::class.memberProperties.first { it.name == name } as KProperty1<Any, *>
    return property.get(this) as R
}
