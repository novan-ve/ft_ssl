/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_calc.c                                          :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <novan-ve@student.codam.nl>         +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/12/18 12:27:09 by novan-ve      #+#    #+#                 */
/*   Updated: 2022/05/25 14:31:46 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_strrev(t_print *p, int len)
{
	char	tmp[len];
	int		i;
	int		j;

	i = 0;
	j = 0;
	while (p->hex[i] != '\0')
	{
		tmp[i] = p->hex[i];
		i++;
	}
	tmp[i] = '\0';
	i--;
	while (i >= 0)
	{
		p->hex[j] = tmp[i];
		i--;
		j++;
	}
	p->hex[j] = '\0';
	p->tmplen = ft_strlen(p->hex);
}

void	ft_dec_to_hex2(t_print *p, unsigned long dec, int x, int len)
{
	unsigned long	remainder;
	int				i;

	i = 0;
	if (dec == 4294967296 && len == 16)
	{
		dec = 0;
		i = 1;
	}
	while (dec != 0)
	{
		remainder = dec % 16;
		if (remainder < 10)
			p->hex[i] = 48 + remainder;
		else
			p->hex[i] = x + remainder;
		dec /= 16;
		i++;
	}
	p->hex[i] = '\0';
	ft_strrev(p, len);
}

void	ft_dec_to_hex(t_print *p, unsigned long dec, int x, int len)
{
	if (x == 0)
		x = 87;
	else if (x == 1)
		x = 55;
	if (dec != 0 || p->var != 'p')
		ft_dec_to_hex2(p, dec, x, len);
	else
	{
		p->hex[0] = '\0';
		p->tmplen = 5;
	}
}

void	ft_calcwidth2(t_print *p, int x, int j)
{
	if (x == 0)
	{
		p->var = p->format[j];
		if (p->minus == 1)
		{
			p->just = 'r';
			p->padchar = ' ';
		}
	}
	else if (x == 1 && p->format[p->i] == '.')
	{
		j = 0;
		p->padchar = ' ';
		p->prec = 0;
		while (ft_isalpha(p->format[p->i]) == 0 && p->format[p->i] != '\0')
		{
			if (p->format[p->i] == '%')
				break ;
			if (p->format[p->i] == '*')
				p->prec = va_arg(p->args, int);
			if (p->format[p->i] >= '0' && p->format[p->i] <= '9')
				p->prec = p->prec * 10 + p->format[p->i] - '0';
			p->i++;
		}
	}
}

void	ft_calcwidth(t_print *p)
{
	int		j;

	j = p->i;
	while (ft_isalpha(p->format[j]) == 0 && p->format[j] != '\0')
	{
		if (p->format[j] == '0' && p->format[j - 1] == '%')
			p->padchar = '0';
		else if (p->format[j] == '-')
			p->minus = 1;
		j++;
	}
	ft_calcwidth2(p, 0, j);
	while (ft_isalpha(p->format[p->i]) == 0 && p->format[p->i] != '\0')
	{
		if (p->format[p->i] == '%')
			break ;
		if (p->format[p->i] == '*')
			p->tmpwidth = va_arg(p->args, int);
		if (p->format[p->i] == '.')
			break ;
		if (p->format[p->i] >= '0' && p->format[p->i] <= '9')
			p->tmpwidth = p->tmpwidth * 10 + p->format[p->i] - '0';
		p->i++;
	}
	ft_calcwidth2(p, 1, j);
}
