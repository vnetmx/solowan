
#ifndef AS_H_
#define AS_H_

typedef void* as;   /* Tipo abstracto que representa la tabla
                       asociativa y que contiene un puntero
                       a la información necesaria.  */

int as_crear(as *pt, size_t nreg, size_t lvalor);
    /*	 Crea una tabla en memoria, dimensionada para "nreg" registros.
	 El valor retornado es 1 si no falla y 0 si falla.
	 Los registros son de longitud variable "lvalor" octetos */

int as_cerrar(as t);
    /*   Cerrar la tabla, liberando los recursos asignados a ella.
         El valor retornado es 1 si no falla y 0 si falla.  */

int as_leer(as t, const size_t pos, void* pv);
    /*   Lee el valor almacenado en la posicion pos. Si no existe
	 el registro, falla.
         El valor retornado es 1 si no falla y 0 si falla.  */

int as_escribir(as t, const size_t pos, const void* pv);
    /*   Escribe un registro, dada su posicion y el valor asociado.
         Si existe el valor en esa posicion, lo reescribe.
         El valor retornado es 1 si no falla y 0 si falla.  */

int as_borrar(as t, const size_t pos);
    /*   Borra un registro en la posicion pos.  El valor retornado es
         siempre 1 (suponemos que no falla).  */

int as_llenos(as t);
/*   Devuelve el numero de registros almacenados  */

#endif /* AS_H_ */
